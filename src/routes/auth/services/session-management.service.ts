import { Injectable, Logger, HttpStatus } from '@nestjs/common'
import { BaseAuthService } from './base-auth.service'
import { REDIS_KEY_PREFIX } from 'src/shared/constants/redis.constants'
import { ActiveSessionSchema, DeviceInfoSchema } from '../dtos/session-management.dto'
import { z } from 'zod'
import { UAParser } from 'ua-parser-js'
import { Device } from '@prisma/client'
import { ApiException } from 'src/shared/exceptions/api.exception'
import { I18nContext } from 'nestjs-i18n'
import { AuditLogStatus, AuditLogData } from 'src/routes/audit-log/audit-log.service'
import { Prisma } from '@prisma/client'
import { PaginatedResponseType } from 'src/shared/models/pagination.model'

type ActiveSessionType = z.infer<typeof ActiveSessionSchema>
type DeviceInfoType = z.infer<typeof DeviceInfoSchema>

@Injectable()
export class SessionManagementService extends BaseAuthService {
  private readonly sessionManagementLogger = new Logger(SessionManagementService.name)

  private _normalizeDeviceType(
    parsedDeviceType?: string,
    osName?: string,
    browserName?: string
  ): ActiveSessionType['device']['type'] {
    switch (parsedDeviceType) {
      case 'console':
      case 'mobile':
      case 'tablet':
      case 'wearable':
        return parsedDeviceType
      case 'smarttv':
        return 'tv'
      // Thêm các case khác từ ua-parser-js nếu cần
      // ví dụ: 'embedded' có thể map sang 'unknown' hoặc một enum mới nếu bạn muốn hỗ trợ
      default:
        // Nếu không có device type cụ thể từ parser, nhưng có OS và browser, khả năng cao là desktop
        if (osName && browserName && !parsedDeviceType) {
          return 'desktop'
        }
        // Nếu parsedDeviceType có giá trị nhưng không nằm trong các case trên, hoặc không có os/browser
        // thì coi là 'unknown'
        return 'unknown'
    }
  }

  async getActiveSessions(
    userId: number,
    currentSessionId: string,
    currentDeviceId: number
  ): Promise<PaginatedResponseType<ActiveSessionType>> {
    const userSessionsKey = `${REDIS_KEY_PREFIX.USER_SESSIONS}${userId}`
    const sessionIds = await this.redisService.smembers(userSessionsKey)
    const activeSessionsData: ActiveSessionType[] = []
    const sessionDetailsList: Array<Record<string, string> & { originalSessionId: string }> = []
    const deviceIdsToFetch = new Set<number>()

    if (sessionIds.length === 0) {
      return {
        data: [],
        totalItems: 0,
        page: 1,
        limit: 0,
        totalPages: 0
      }
    }

    // Bước 1: Lấy tất cả chi tiết session từ Redis
    const redisPipeline = this.redisService.client.pipeline()
    sessionIds.forEach((sessionId) => {
      redisPipeline.hgetall(`${REDIS_KEY_PREFIX.SESSION_DETAILS}${sessionId}`)
    })
    const results = await redisPipeline.exec()

    if (!results) {
      this.sessionManagementLogger.warn(`Pipeline to fetch session details for user ${userId} returned null.`)
      return {
        data: [],
        totalItems: 0,
        page: 1,
        limit: 0,
        totalPages: 0
      }
    }

    for (let i = 0; i < results.length; i++) {
      const pipelineItem = results[i]
      if (!pipelineItem) {
        this.sessionManagementLogger.warn(`Pipeline result item at index ${i} for user ${userId} is null. Skipping.`)
        continue
      }

      const [err, dataFromRedis] = pipelineItem // dataFromRedis is 'any'

      if (err) {
        this.sessionManagementLogger.warn(
          `Error in Redis pipeline for session ${sessionIds[i]} (user ${userId}): ${err.message}. Skipping.`
        )
        continue
      }

      if (typeof dataFromRedis !== 'object' || dataFromRedis === null) {
        this.sessionManagementLogger.warn(
          `Invalid data type for session ${sessionIds[i]} (user ${userId}): expected object, got ${typeof dataFromRedis}. Skipping.`
        )
        continue
      }

      const sessionDetails = dataFromRedis as Record<string, string>

      if (Object.keys(sessionDetails).length === 0) {
        this.sessionManagementLogger.warn(`Empty session data for session ${sessionIds[i]} (user ${userId}). Skipping.`)
        continue
      }

      if (
        !sessionDetails.createdAt ||
        !sessionDetails.lastActiveAt ||
        !sessionDetails.deviceId ||
        !sessionDetails.userId ||
        parseInt(sessionDetails.userId, 10) !== userId
      ) {
        this.sessionManagementLogger.warn(
          `Session ${sessionIds[i]} for user ${
            sessionDetails.userId || 'UNKNOWN'
          } is missing critical details or userId mismatch. Skipping.`
        )
        continue
      }
      sessionDetailsList.push({ ...sessionDetails, originalSessionId: sessionIds[i] })
      const deviceIdFromSession = parseInt(sessionDetails.deviceId, 10)
      if (!isNaN(deviceIdFromSession)) {
        deviceIdsToFetch.add(deviceIdFromSession)
      }
    }

    // Bước 2: Lấy tất cả device info từ DB một lần
    let devicesMap = new Map<number, Device>()
    if (deviceIdsToFetch.size > 0) {
      const dbDevices = await this.prismaService.device.findMany({
        where: {
          id: { in: Array.from(deviceIdsToFetch) },
          userId: userId // Ensure devices belong to the user
        }
      })
      devicesMap = new Map(dbDevices.map((device) => [device.id, device]))
    }

    // Bước 3: Xây dựng kết quả
    for (const sessionDetails of sessionDetailsList) {
      const loggedInAtDate = new Date(sessionDetails.createdAt)
      const lastActiveAtDate = new Date(sessionDetails.lastActiveAt)

      if (isNaN(loggedInAtDate.getTime()) || isNaN(lastActiveAtDate.getTime())) {
        this.sessionManagementLogger.warn(
          `Session ${sessionDetails.originalSessionId} for user ${sessionDetails.userId} has invalid date formats. Skipping.`
        )
        continue
      }

      const deviceIdFromSession = parseInt(sessionDetails.deviceId, 10)
      const dbDevice = devicesMap.get(deviceIdFromSession)
      const deviceName = dbDevice?.name || null

      const uaParser = new UAParser(sessionDetails.userAgent)
      const browser = uaParser.getBrowser()
      const os = uaParser.getOS()
      const parsedDeviceType = uaParser.getDevice().type

      const type = this._normalizeDeviceType(parsedDeviceType, os.name, browser.name)

      const location = sessionDetails.ipAddress ? this.geolocationService.lookup(sessionDetails.ipAddress) : null
      const locationString = location
        ? `${location.city || 'Unknown City'}, ${location.country || 'Unknown Country'}`
        : 'Location unknown'

      let validIpAddress: string | null = null
      if (sessionDetails.ipAddress && sessionDetails.ipAddress.trim() !== '') {
        try {
          z.string().ip().parse(sessionDetails.ipAddress)
          validIpAddress = sessionDetails.ipAddress
        } catch (e) {
          this.sessionManagementLogger.warn(
            `Session ${sessionDetails.originalSessionId} has an invalid IP address format ('${sessionDetails.ipAddress}'). Setting to null.`
          )
        }
      }

      activeSessionsData.push({
        sessionId: sessionDetails.originalSessionId,
        device: {
          id: deviceIdFromSession,
          name: deviceName,
          type: type,
          os: os.name && os.version ? `${os.name} ${os.version}` : os.name || null,
          browser: browser.name && browser.version ? `${browser.name} ${browser.version}` : browser.name || null,
          isCurrentDevice:
            deviceIdFromSession === currentDeviceId && sessionDetails.originalSessionId === currentSessionId
        },
        ipAddress: validIpAddress,
        location: locationString,
        loggedInAt: loggedInAtDate.toISOString(),
        lastActiveAt: lastActiveAtDate.toISOString(),
        isCurrentSession: sessionDetails.originalSessionId === currentSessionId
      })
    }

    activeSessionsData.sort((a, b) => {
      if (a.isCurrentSession) return -1
      if (b.isCurrentSession) return 1
      return new Date(b.lastActiveAt).getTime() - new Date(a.lastActiveAt).getTime()
    })

    // Wrap in paginated response structure
    return {
      data: activeSessionsData,
      totalItems: activeSessionsData.length,
      page: 1, // Default to page 1 as no pagination params are taken
      limit: activeSessionsData.length > 0 ? activeSessionsData.length : 1, // Avoid limit 0
      totalPages: 1 // Default to 1 total page
    }
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

  async getManagedDevices(userId: number): Promise<PaginatedResponseType<DeviceInfoType>> {
    const devicesFromDb = await this.prismaService.device.findMany({
      where: { userId },
      orderBy: { lastActive: 'desc' }
    })

    const devicesData: DeviceInfoType[] = devicesFromDb.map((device) => {
      const uaParser = new UAParser(device.userAgent)
      const browser = uaParser.getBrowser()
      const os = uaParser.getOS()
      const parsedDeviceType = uaParser.getDevice().type

      const type = this._normalizeDeviceType(parsedDeviceType, os.name, browser.name)

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
        type: type,
        os: os.name && os.version ? `${os.name} ${os.version}` : os.name || null,
        browser: browser.name && browser.version ? `${browser.name} ${browser.version}` : browser.name || null,
        ip: device.ip,
        location,
        createdAt: device.createdAt.toISOString(),
        lastActive: device.lastActive.toISOString(),
        isTrusted: device.isTrusted
      }
    })

    // Wrap in paginated response structure
    return {
      data: devicesData,
      totalItems: devicesData.length,
      page: 1, // Default to page 1
      limit: devicesData.length > 0 ? devicesData.length : 1, // Avoid limit 0
      totalPages: 1 // Default to 1 total page
    }
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
