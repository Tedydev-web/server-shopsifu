import { Injectable, Logger, HttpStatus } from '@nestjs/common'
import { BaseAuthService } from './base-auth.service'
import { REDIS_KEY_PREFIX } from 'src/shared/constants/redis.constants'
import { ActiveSessionSchema, DeviceInfoSchema } from '../dtos/session-management.dto'
import { z } from 'zod'
import { UAParser } from 'ua-parser-js'
import { Device, User } from '@prisma/client'
import { ApiException } from 'src/shared/exceptions/api.exception'
import { I18nContext } from 'nestjs-i18n'
import { AuditLogStatus, AuditLogData } from 'src/routes/audit-log/audit-log.service'
import { Prisma } from '@prisma/client'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'

type ActiveSessionType = z.infer<typeof ActiveSessionSchema>
type DeviceInfoType = z.infer<typeof DeviceInfoSchema>

@Injectable()
export class SessionManagementService extends BaseAuthService {
  private readonly sessionManagementLogger = new Logger(SessionManagementService.name)

  async getActiveSessions(
    userId: number,
    currentSessionId: string,
    currentDeviceId: number
  ): Promise<ActiveSessionType[]> {
    const userSessionsKey = `${REDIS_KEY_PREFIX.USER_SESSIONS}${userId}`
    const sessionIds = await this.redisService.smembers(userSessionsKey)
    const activeSessions: ActiveSessionType[] = []

    for (const sessionId of sessionIds) {
      const sessionKey = `${REDIS_KEY_PREFIX.SESSION_DETAILS}${sessionId}`
      const sessionDetails = await this.redisService.hgetall(sessionKey)

      if (sessionDetails && Object.keys(sessionDetails).length > 0) {
        // Validate required fields from Redis before proceeding
        if (
          !sessionDetails.createdAt ||
          !sessionDetails.lastActiveAt ||
          !sessionDetails.deviceId ||
          !sessionDetails.userId
        ) {
          this.sessionManagementLogger.warn(
            `Session ${sessionId} for user ${sessionDetails.userId || 'UNKNOWN'} is missing critical details (createdAt, lastActiveAt, userId, or deviceId) in Redis. Skipping.`
          )
          continue // Skip this problematic session
        }

        // Validate date strings
        const loggedInAtDate = new Date(sessionDetails.createdAt)
        const lastActiveAtDate = new Date(sessionDetails.lastActiveAt)

        if (isNaN(loggedInAtDate.getTime()) || isNaN(lastActiveAtDate.getTime())) {
          this.sessionManagementLogger.warn(
            `Session ${sessionId} for user ${sessionDetails.userId} has invalid date formats for createdAt ('${sessionDetails.createdAt}') or lastActiveAt ('${sessionDetails.lastActiveAt}') in Redis. Skipping.`
          )
          continue
        }

        const deviceIdFromSession = parseInt(sessionDetails.deviceId, 10)
        let deviceName: string | null = null
        let dbDevice: Device | null = null

        if (!isNaN(deviceIdFromSession)) {
          dbDevice = await this.prismaService.device.findUnique({ where: { id: deviceIdFromSession } })
          deviceName = dbDevice?.name || null
        }

        const uaParser = new UAParser(sessionDetails.userAgent)
        const browser = uaParser.getBrowser()
        const os = uaParser.getOS()
        const deviceTypeParsed = uaParser.getDevice().type || 'unknown'

        const location = sessionDetails.ipAddress ? this.geolocationService.lookup(sessionDetails.ipAddress) : null
        const locationString = location
          ? `${location.city || 'Unknown City'}, ${location.country || 'Unknown Country'}`
          : 'Location unknown'

        const ipAddr = sessionDetails.ipAddress
        let validIpAddress: string | null = null
        if (ipAddr && ipAddr.trim() !== '') {
          // Use Zod to validate if it's a valid IP for consistency with the schema
          // We'll use a try-catch here as we don't want to break the loop for one bad IP.
          try {
            z.string().ip().parse(ipAddr) // This will throw if ipAddr is not a valid IP
            validIpAddress = ipAddr
          } catch (e) {
            this.sessionManagementLogger.warn(
              `Session ${sessionId} for user ${sessionDetails.userId} has an invalid IP address format ('${ipAddr}') in Redis. Setting to null.`
            )
            // validIpAddress remains null
          }
        }

        activeSessions.push({
          sessionId: sessionId,
          device: {
            id: deviceIdFromSession,
            name: deviceName,
            type: deviceTypeParsed as 'desktop' | 'mobile' | 'tablet' | 'unknown',
            os: os.name && os.version ? `${os.name} ${os.version}` : os.name || null,
            browser: browser.name && browser.version ? `${browser.name} ${browser.version}` : browser.name || null,
            isCurrentDevice: deviceIdFromSession === currentDeviceId && sessionId === currentSessionId
          },
          ipAddress: validIpAddress,
          location: locationString,
          loggedInAt: loggedInAtDate.toISOString(),
          lastActiveAt: lastActiveAtDate.toISOString(),
          isCurrentSession: sessionId === currentSessionId
        })
      }
    }

    activeSessions.sort((a, b) => {
      if (a.isCurrentSession) return -1
      if (b.isCurrentSession) return 1
      return new Date(b.lastActiveAt).getTime() - new Date(a.lastActiveAt).getTime()
    })
    return activeSessions
  }

  async revokeSession(
    userId: number,
    sessionIdToRevoke: string,
    currentSessionId: string
  ): Promise<{ message: string }> {
    const auditLogEntry: Partial<AuditLogData> = {
      action: 'SESSION_REVOKE_ATTEMPT',
      userId,
      status: AuditLogStatus.FAILURE,
      details: { sessionIdToRevoke } as Prisma.JsonObject
    }

    if (sessionIdToRevoke === currentSessionId) {
      auditLogEntry.errorMessage = 'Cannot revoke current session via this endpoint. Use logout.'
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      throw new ApiException(
        HttpStatus.BAD_REQUEST,
        'CANNOT_REVOKE_CURRENT_SESSION',
        'Error.Auth.Session.CannotRevokeCurrent'
      )
    }

    const sessionDetailsKey = `${REDIS_KEY_PREFIX.SESSION_DETAILS}${sessionIdToRevoke}`
    const sessionData = await this.redisService.hgetall(sessionDetailsKey)

    if (Object.keys(sessionData).length === 0 || parseInt(sessionData.userId, 10) !== userId) {
      auditLogEntry.errorMessage = 'Session not found or does not belong to the user.'
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      throw new ApiException(HttpStatus.NOT_FOUND, 'SESSION_NOT_FOUND', 'Error.Auth.Session.NotFound')
    }

    await this.tokenService.invalidateSession(sessionIdToRevoke, 'USER_MANUAL_REVOKE')

    auditLogEntry.status = AuditLogStatus.SUCCESS
    auditLogEntry.action = 'SESSION_REVOKE_SUCCESS'
    await this.auditLogService.record(auditLogEntry as AuditLogData)

    const message = await this.i18nService.translate('error.Auth.Session.RevokedSuccessfully', {
      lang: I18nContext.current()?.lang
    })
    return { message }
  }

  async getManagedDevices(userId: number): Promise<DeviceInfoType[]> {
    const devices = await this.prismaService.device.findMany({
      where: { userId },
      orderBy: { lastActive: 'desc' }
    })

    return devices.map((device) => {
      const uaParser = new UAParser(device.userAgent)
      const browser = uaParser.getBrowser()
      const os = uaParser.getOS()
      const deviceTypeParsed = uaParser.getDevice().type || 'unknown'
      let location: string | null = device.ip || null
      if (device.ip) {
        const geo = this.geolocationService.lookup(device.ip)
        if (geo && geo.city && geo.country) {
          location = `${geo.city}, ${geo.country}`
        }
      }

      return {
        id: device.id,
        name: device.name,
        type: deviceTypeParsed as 'desktop' | 'mobile' | 'tablet' | 'unknown',
        os: os.name && os.version ? `${os.name} ${os.version}` : os.name || null,
        browser: browser.name && browser.version ? `${browser.name} ${browser.version}` : browser.name || null,
        ip: device.ip,
        location,
        createdAt: device.createdAt.toISOString(),
        lastActive: device.lastActive.toISOString(),
        isTrusted: device.isTrusted
      }
    })
  }

  async updateDeviceName(userId: number, deviceId: number, name: string): Promise<{ message: string }> {
    const device = await this.prismaService.device.findUnique({ where: { id: deviceId } })
    if (!device || device.userId !== userId) {
      throw new ApiException(HttpStatus.NOT_FOUND, 'DEVICE_NOT_FOUND', 'Error.Auth.Device.NotFound')
    }

    await this.prismaService.device.update({
      where: { id: deviceId },
      data: { name }
    })

    this.auditLogService.record({
      action: 'DEVICE_NAME_UPDATE',
      userId,
      entity: 'Device',
      entityId: deviceId,
      status: AuditLogStatus.SUCCESS,
      details: { oldName: device.name, newName: name } as Prisma.JsonObject
    })

    const message = await this.i18nService.translate('error.Auth.Device.NameUpdatedSuccessfully', {
      lang: I18nContext.current()?.lang
    })
    return { message }
  }

  async trustManagedDevice(userId: number, deviceId: number): Promise<{ message: string }> {
    const device = await this.deviceService.trustDevice(deviceId, userId)

    // Also update all active sessions for this device on Redis to reflect trusted status
    const userSessionsKey = `${REDIS_KEY_PREFIX.USER_SESSIONS}${userId}`
    const sessionIds = await this.redisService.smembers(userSessionsKey)
    for (const sessionId of sessionIds) {
      const sessionDetailsKey = `${REDIS_KEY_PREFIX.SESSION_DETAILS}${sessionId}`
      const sessionDeviceId = await this.redisService.hget(sessionDetailsKey, 'deviceId')
      if (sessionDeviceId && parseInt(sessionDeviceId, 10) === deviceId) {
        await this.redisService.hset(sessionDetailsKey, 'isTrusted', 'true')
      }
    }

    this.auditLogService.record({
      action: 'DEVICE_TRUST_MANAGED',
      userId,
      entity: 'Device',
      entityId: deviceId,
      status: AuditLogStatus.SUCCESS,
      details: { deviceUserAgent: device.userAgent } as Prisma.JsonObject
    })
    const message = await this.i18nService.translate('error.Auth.Device.Trusted', {
      lang: I18nContext.current()?.lang
    })
    return { message }
  }

  async untrustManagedDevice(userId: number, deviceId: number): Promise<{ message: string }> {
    const device = await this.prismaService.device.findUnique({ where: { id: deviceId } })
    if (!device || device.userId !== userId) {
      throw new ApiException(HttpStatus.NOT_FOUND, 'DEVICE_NOT_FOUND', 'Error.Auth.Device.NotFound')
    }

    await this.prismaService.device.update({
      where: { id: deviceId },
      data: { isTrusted: false }
    })

    // Also update all active sessions for this device on Redis
    const userSessionsKey = `${REDIS_KEY_PREFIX.USER_SESSIONS}${userId}`
    const sessionIds = await this.redisService.smembers(userSessionsKey)
    for (const sessionId of sessionIds) {
      const sessionDetailsKey = `${REDIS_KEY_PREFIX.SESSION_DETAILS}${sessionId}`
      const sessionDeviceId = await this.redisService.hget(sessionDetailsKey, 'deviceId')
      if (sessionDeviceId && parseInt(sessionDeviceId, 10) === deviceId) {
        await this.redisService.hset(sessionDetailsKey, 'isTrusted', 'false')
      }
    }

    this.auditLogService.record({
      action: 'DEVICE_UNTRUST_MANAGED',
      userId,
      entity: 'Device',
      entityId: deviceId,
      status: AuditLogStatus.SUCCESS,
      details: { deviceUserAgent: device.userAgent } as Prisma.JsonObject
    })

    const message = await this.i18nService.translate('error.Auth.Device.Untrusted', {
      lang: I18nContext.current()?.lang
    })
    return { message }
  }

  async logoutFromManagedDevice(
    userId: number, // User whose device is being logged out
    deviceIdToLogout: number,
    actionPerformer: { userId: number; ipAddress?: string; userAgent?: string } // User performing the action
  ): Promise<{ message: string }> {
    const auditLogEntry: Partial<AuditLogData> = {
      action: 'DEVICE_LOGOUT_MANAGED_ATTEMPT',
      userId: actionPerformer.userId, // User performing the action
      ipAddress: actionPerformer.ipAddress,
      userAgent: actionPerformer.userAgent,
      status: AuditLogStatus.FAILURE,
      details: { targetDeviceId: deviceIdToLogout, targetUserId: userId } as Prisma.JsonObject
    }

    const deviceToLogout = await this.prismaService.device.findUnique({ where: { id: deviceIdToLogout } })
    if (!deviceToLogout || deviceToLogout.userId !== userId) {
      auditLogEntry.errorMessage = 'Device not found or does not belong to the specified user.'
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      throw new ApiException(HttpStatus.NOT_FOUND, 'DEVICE_NOT_FOUND', 'Error.Auth.Device.NotFoundForUser')
    }

    if (auditLogEntry.details && typeof auditLogEntry.details === 'object') {
      ;(auditLogEntry.details as Prisma.JsonObject).loggedOutDeviceUserAgent = deviceToLogout.userAgent
    }

    // Invalidate all sessions associated with this device ID
    const userSessionsKey = `${REDIS_KEY_PREFIX.USER_SESSIONS}${userId}`
    const sessionIds = await this.redisService.smembers(userSessionsKey)
    let sessionsInvalidatedCount = 0

    for (const sessionId of sessionIds) {
      const sessionDetailsKey = `${REDIS_KEY_PREFIX.SESSION_DETAILS}${sessionId}`
      const sessionDeviceId = await this.redisService.hget(sessionDetailsKey, 'deviceId')
      if (sessionDeviceId && parseInt(sessionDeviceId, 10) === deviceIdToLogout) {
        await this.tokenService.invalidateSession(sessionId, 'ADMIN_DEVICE_LOGOUT')
        sessionsInvalidatedCount++
      }
    }

    // Optionally, mark the device as inactive in Prisma if desired, though sessions are the primary target
    // await this.prismaService.device.update({ where: { id: deviceIdToLogout }, data: { isActive: false } });

    auditLogEntry.status = AuditLogStatus.SUCCESS
    auditLogEntry.action = 'DEVICE_LOGOUT_MANAGED_SUCCESS'
    if (auditLogEntry.details && typeof auditLogEntry.details === 'object') {
      ;(auditLogEntry.details as Prisma.JsonObject).sessionsInvalidated = sessionsInvalidatedCount
    }
    await this.auditLogService.record(auditLogEntry as AuditLogData)

    const message = await this.i18nService.translate('error.Auth.Device.LogoutSpecificSuccess', {
      lang: I18nContext.current()?.lang
    })
    return { message }
  }
}
