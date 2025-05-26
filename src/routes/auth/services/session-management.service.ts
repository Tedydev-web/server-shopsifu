import { Injectable, Logger, HttpStatus } from '@nestjs/common'
import { BaseAuthService } from './base-auth.service'
import { REDIS_KEY_PREFIX } from 'src/shared/constants/redis.constants'
import {
  ActiveSessionSchema,
  DeviceInfoSchema,
  GetActiveSessionsResSchema,
  RevokeSessionsBodyDTO
} from '../dtos/session-management.dto'
import { z } from 'zod'
import { UAParser } from 'ua-parser-js'
import { Device } from '@prisma/client'
import { ApiException } from 'src/shared/exceptions/api.exception'
import { I18nContext } from 'nestjs-i18n'
import { AuditLogStatus, AuditLogData } from 'src/routes/audit-log/audit-log.service'
import { Prisma } from '@prisma/client'
import { PaginatedResponseType } from 'src/shared/models/pagination.model'
import { SessionNotFoundException } from '../auth.error'
import envConfig from 'src/shared/config'

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
    currentDeviceId: number,
    filterByDeviceId?: number
  ): Promise<PaginatedResponseType<ActiveSessionType>> {
    this.sessionManagementLogger.debug(
      `Fetching active sessions for user ${userId}, currentSessionId: ${currentSessionId}, currentDeviceId: ${currentDeviceId}, filterByDeviceId: ${filterByDeviceId}`
    )
    const userSessionKeys = await this.redisService.smembers(`${REDIS_KEY_PREFIX.USER_SESSIONS}${userId}`)
    if (!userSessionKeys || userSessionKeys.length === 0) {
      return {
        data: [],
        totalItems: 0,
        page: 1,
        limit: 0,
        totalPages: 0
      }
    }

    const activeSessionsData: ActiveSessionType[] = []
    const sessionDetailsList: Array<Record<string, string> & { originalSessionId: string }> = []
    const deviceIdsToFetch = new Set<number>()

    // Bước 1: Lấy tất cả chi tiết session từ Redis
    const redisPipeline = this.redisService.client.pipeline()
    userSessionKeys.forEach((sessionId) => {
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
          `Error in Redis pipeline for session ${userSessionKeys[i]} (user ${userId}): ${err.message}. Skipping.`
        )
        continue
      }

      if (typeof dataFromRedis !== 'object' || dataFromRedis === null) {
        this.sessionManagementLogger.warn(
          `Invalid data type for session ${userSessionKeys[i]} (user ${userId}): expected object, got ${typeof dataFromRedis}. Skipping.`
        )
        continue
      }

      const sessionDetails = dataFromRedis as Record<string, string>

      if (Object.keys(sessionDetails).length === 0) {
        this.sessionManagementLogger.warn(
          `Empty session data for session ${userSessionKeys[i]} (user ${userId}). Skipping.`
        )
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
          `Session ${userSessionKeys[i]} for user ${
            sessionDetails.userId || 'UNKNOWN'
          } is missing critical details or userId mismatch. Skipping.`
        )
        continue
      }

      // Apply deviceId filter if provided
      if (filterByDeviceId !== undefined && parseInt(sessionDetails.deviceId, 10) !== filterByDeviceId) {
        continue
      }

      sessionDetailsList.push({ ...sessionDetails, originalSessionId: userSessionKeys[i] })
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
    this.sessionManagementLogger.debug(`User ${userId} fetching managed devices.`)
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

  /**
   * @deprecated Use revokeMultipleSessions with deviceId and ensure the new method also untrusts the device if needed.
   */
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

  async trustCurrentDevice(userId: number, deviceId: number): Promise<{ message: string }> {
    this.sessionManagementLogger.debug(`User ${userId} attempting to trust current device ${deviceId}`)
    // This can directly call trustManagedDevice as the logic is the same.
    // trustManagedDevice already handles audit logging.
    return this.trustManagedDevice(userId, deviceId)
  }

  async revokeMultipleSessions(
    userId: number,
    currentSessionId: string,
    body: RevokeSessionsBodyDTO // Use the imported DTO
  ): Promise<{ message: string }> {
    const { sessionIds, deviceId, revokeAll } = body
    let sessionsToRevoke: string[] = []
    let actionDescription = ''
    let deviceToUntrust: number | null = null

    const auditDetails: Prisma.JsonObject = {
      revokedByUserId: userId,
      currentSessionId,
      requestBody: body as unknown as Prisma.JsonObject // body is already an object
    }

    if (revokeAll) {
      actionDescription = 'Revoke all user sessions (excluding current)'
      this.sessionManagementLogger.debug(
        `User ${userId} attempting to revoke all sessions (excluding current: ${currentSessionId}).`
      )
      const allUserSessions = await this.redisService.smembers(`${REDIS_KEY_PREFIX.USER_SESSIONS}${userId}`)
      sessionsToRevoke = allUserSessions.filter((sid) => sid !== currentSessionId)
      auditDetails.revokeAllTriggered = true
    } else if (deviceId) {
      actionDescription = `Revoke all sessions for device ${deviceId} and untrust it`
      this.sessionManagementLogger.debug(
        `User ${userId} attempting to revoke all sessions for device ${deviceId} and untrust it.`
      )
      if (!(await this.deviceService.isDeviceOwnedByUser(deviceId, userId))) {
        throw SessionNotFoundException // Or a more specific "DeviceNotOwned" exception
      }

      const allUserSessions = await this.redisService.smembers(`${REDIS_KEY_PREFIX.USER_SESSIONS}${userId}`)
      for (const sid of allUserSessions) {
        const sessionData = await this.redisService.hgetall(`${REDIS_KEY_PREFIX.SESSION_DETAILS}${sid}`)
        if (sessionData && parseInt(sessionData.deviceId, 10) === deviceId) {
          // For revoking a device, we revoke all its sessions, including the current one if it's on that device.
          sessionsToRevoke.push(sid)
        }
      }
      deviceToUntrust = deviceId
      auditDetails.revokedDeviceId = deviceId
    } else if (sessionIds && sessionIds.length > 0) {
      actionDescription = `Revoke specific sessions: ${sessionIds.join(', ')}`
      this.sessionManagementLogger.debug(
        `User ${userId} attempting to revoke specific sessions: ${sessionIds.join(', ')} (current: ${currentSessionId}).`
      )
      sessionsToRevoke = sessionIds.filter((sid) => {
        if (sid === currentSessionId) {
          this.sessionManagementLogger.warn(
            `User ${userId} attempted to revoke current session ${currentSessionId} via sessionIds array. This is disallowed.`
          )
          // Optionally throw an error or just silently ignore
          // For now, silently ignore to prevent accidental self-lockout through this specific path.
          // The `deviceId` path has different semantics (logout from a device entirely).
          return false
        }
        return true
      })
      auditDetails.specificSessionIdsRequested = sessionIds as Prisma.JsonArray
    } else {
      // This case should be caught by Zod validation, but as a safeguard:
      throw new ApiException(HttpStatus.BAD_REQUEST, 'InvalidInput', 'Error.Auth.Session.InvalidRevokeOperation')
    }

    if (sessionsToRevoke.length === 0 && !deviceToUntrust) {
      const message = await this.i18nService.translate('error.Auth.Session.NoSessionsToRevoke', {
        lang: I18nContext.current()?.lang
      })
      return { message }
    }

    let revokedCount = 0
    for (const sid of sessionsToRevoke) {
      try {
        // Check if session belongs to the user before revoking, as an extra security measure.
        const sessionOwnerId = await this.redisService.hget(`${REDIS_KEY_PREFIX.SESSION_DETAILS}${sid}`, 'userId')
        if (sessionOwnerId && parseInt(sessionOwnerId, 10) === userId) {
          await this.tokenService.invalidateSession(sid, `USER_REQUEST_REVOKE_MULTIPLE (${actionDescription})`)
          revokedCount++
        } else {
          this.sessionManagementLogger.warn(
            `User ${userId} attempted to revoke session ${sid} not belonging to them or session details missing.`
          )
        }
      } catch (error) {
        this.sessionManagementLogger.error(`Error revoking session ${sid} for user ${userId}: ${error.message}`)
        // Continue to revoke other sessions
      }
    }

    auditDetails.sessionsActuallyRevoked = sessionsToRevoke as Prisma.JsonArray
    auditDetails.revokedCount = revokedCount

    if (deviceToUntrust !== null) {
      try {
        await this.untrustManagedDevice(userId, deviceToUntrust) // This also handles audit logging for untrust
        auditDetails.deviceUntrusted = true
      } catch (error) {
        this.sessionManagementLogger.error(
          `Error untrusting device ${deviceToUntrust} for user ${userId} after revoking its sessions: ${error.message}`
        )
        auditDetails.deviceUntrustFailed = error.message
      }
    }

    await this.auditLogService.successSync('REVOKE_SESSIONS', {
      userId,
      details: auditDetails,
      notes: `${actionDescription}. Revoked ${revokedCount} session(s).`
    })

    const message = await this.i18nService.translate('error.Auth.Session.RevokedSuccessfullyCount', {
      lang: I18nContext.current()?.lang,
      args: { count: revokedCount }
    })
    return { message }
  }

  async enforceSessionAndDeviceLimits(
    userId: number,
    currentSessionIdToExclude?: string,
    currentDeviceIdToExclude?: number
  ): Promise<{
    devicesRemovedCount: number
    sessionsRevokedCount: number
    deviceLimitApplied: boolean
    sessionLimitApplied: boolean
  }> {
    this.sessionManagementLogger.debug(
      `Enforcing session and device limits for user ${userId}. Current session: ${currentSessionIdToExclude}, current device: ${currentDeviceIdToExclude}`
    )
    let devicesRemovedCount = 0
    let sessionsRevokedCount = 0
    let deviceLimitApplied = false
    let sessionLimitApplied = false

    // Enforce max active sessions
    const maxSessions = envConfig.MAX_SESSIONS_PER_USER // Corrected from MAX_ACTIVE_SESSIONS_PER_USER
    const userSessionsKey = `${REDIS_KEY_PREFIX.USER_SESSIONS}${userId}`
    const allSessionIds = await this.redisService.smembers(userSessionsKey)

    // --- Device Limit Enforcement ---
    if (maxSessions > 0) {
      const userDevices = await this.prismaService.device.findMany({
        where: { userId, isActive: true },
        orderBy: { lastActive: 'asc' } // Oldest first
      })

      if (userDevices.length > maxSessions) {
        deviceLimitApplied = true
        const devicesToPotentiallyRemove = userDevices.filter((d) => d.id !== currentDeviceIdToExclude)
        let numDevicesToRemove =
          devicesToPotentiallyRemove.length - (maxSessions - (userDevices.length - devicesToPotentiallyRemove.length))
        //This calculation ensures we only consider removable devices to reach the target count.

        if (numDevicesToRemove > 0) {
          this.sessionManagementLogger.log(
            `User ${userId} has ${userDevices.length} active devices, exceeding limit of ${maxSessions}. Attempting to remove ${numDevicesToRemove} devices.`
          )

          // Separate by trust status and sort: untrusted first, then by lastActive
          const sortedDevicesToConsider = devicesToPotentiallyRemove.sort((a, b) => {
            if (a.isTrusted !== b.isTrusted) {
              return a.isTrusted ? 1 : -1 // Untrusted (false) come first
            }
            return new Date(a.lastActive).getTime() - new Date(b.lastActive).getTime() // Oldest lastActive first
          })

          const devicesActuallyRemoved: Device[] = []
          for (const device of sortedDevicesToConsider) {
            if (numDevicesToRemove <= 0) break

            this.sessionManagementLogger.log(
              `Removing device ${device.id} (trusted: ${device.isTrusted}, lastActive: ${device.lastActive.toISOString()}) for user ${userId} due to device limit.`
            )
            // 1. Revoke all sessions for this device
            const deviceSessions = await this.getAllSessionsForDevice(userId, device.id)
            for (const sessionId of deviceSessions) {
              try {
                await this.tokenService.invalidateSession(sessionId, 'DEVICE_LIMIT_EXCEEDED')
                sessionsRevokedCount++
              } catch (e) {
                this.sessionManagementLogger.error(
                  `Failed to invalidate session ${sessionId} for device ${device.id} during device limit enforcement: ${e.message}`
                )
              }
            }
            // 2. Mark device as inactive (and untrust it)
            try {
              await this.prismaService.device.update({
                where: { id: device.id },
                data: {
                  isActive: false,
                  isTrusted: false,
                  name: device.name ? `[Removed] ${device.name}` : '[Removed] Device'
                }
              })
              devicesActuallyRemoved.push(device)
              devicesRemovedCount++
            } catch (e) {
              this.sessionManagementLogger.error(
                `Failed to deactivate/untrust device ${device.id} during device limit enforcement: ${e.message}`
              )
            }
            numDevicesToRemove--
          }
          if (devicesActuallyRemoved.length > 0) {
            await this.auditLogService.recordAsync({
              userId,
              action: 'AUTO_DEVICE_REMOVAL_LIMIT_EXCEEDED',
              status: AuditLogStatus.SUCCESS,
              entity: 'Device',
              details: {
                maxSessions,
                currentDeviceCount: userDevices.length,
                removedDevices: devicesActuallyRemoved.map((d) => ({
                  id: d.id,
                  name: d.name,
                  isTrusted: d.isTrusted,
                  lastActive: d.lastActive.toISOString()
                })),
                sessionsRevokedRelatedToDevices: sessionsRevokedCount
              } as Prisma.JsonObject,
              notes: `Automatically removed ${devicesActuallyRemoved.length} devices and related sessions due to exceeding device limit.`
            })
          }
        }
      }
    }

    // --- Session Limit Enforcement ---
    if (maxSessions > 0) {
      const userSessionIds = await this.redisService.smembers(`${REDIS_KEY_PREFIX.USER_SESSIONS}${userId}`)

      if (userSessionIds.length > maxSessions) {
        sessionLimitApplied = true
        const sessionsToConsider = userSessionIds.filter((sid) => sid !== currentSessionIdToExclude)
        let numSessionsToRemove =
          sessionsToConsider.length - (maxSessions - (userSessionIds.length - sessionsToConsider.length))

        if (numSessionsToRemove > 0) {
          this.sessionManagementLogger.log(
            `User ${userId} has ${userSessionIds.length} active sessions, exceeding limit of ${maxSessions}. Attempting to remove ${numSessionsToRemove} sessions.`
          )

          const sessionDetailsList: Array<{
            sessionId: string
            deviceId: number
            lastActiveAt: Date
            isDeviceTrusted: boolean
          }> = []
          for (const sessionId of sessionsToConsider) {
            const details = await this.redisService.hgetall(`${REDIS_KEY_PREFIX.SESSION_DETAILS}${sessionId}`)
            if (details && details.deviceId && details.lastActiveAt) {
              const device = await this.prismaService.device.findUnique({
                where: { id: parseInt(details.deviceId, 10) }
              })
              sessionDetailsList.push({
                sessionId,
                deviceId: parseInt(details.deviceId, 10),
                lastActiveAt: new Date(details.lastActiveAt),
                isDeviceTrusted: device?.isTrusted || false // Default to not trusted if device not found or no trust status
              })
            }
          }

          // Sort: untrusted devices first, then by lastActiveAt (oldest first)
          sessionDetailsList.sort((a, b) => {
            if (a.isDeviceTrusted !== b.isDeviceTrusted) {
              return a.isDeviceTrusted ? 1 : -1 // Untrusted (false) come first
            }
            return a.lastActiveAt.getTime() - b.lastActiveAt.getTime() // Oldest lastActiveAt first
          })

          const sessionsActuallyRevokedIds: string[] = []
          for (const session of sessionDetailsList) {
            if (numSessionsToRemove <= 0) break
            try {
              this.sessionManagementLogger.log(
                `Revoking session ${session.sessionId} (on device ${session.deviceId}, trusted: ${session.isDeviceTrusted}, lastActive: ${session.lastActiveAt.toISOString()}) for user ${userId} due to session limit.`
              )
              await this.tokenService.invalidateSession(session.sessionId, 'SESSION_LIMIT_EXCEEDED')
              sessionsRevokedCount++
              sessionsActuallyRevokedIds.push(session.sessionId)
            } catch (e) {
              this.sessionManagementLogger.error(
                `Failed to invalidate session ${session.sessionId} during session limit enforcement: ${e.message}`
              )
            }
            numSessionsToRemove--
          }
          if (sessionsActuallyRevokedIds.length > 0) {
            await this.auditLogService.recordAsync({
              userId,
              action: 'AUTO_SESSION_REVOCATION_LIMIT_EXCEEDED',
              status: AuditLogStatus.SUCCESS,
              entity: 'Session',
              details: {
                maxSessions,
                currentSessionCount: userSessionIds.length,
                revokedSessionIds: sessionsActuallyRevokedIds
              } as Prisma.JsonObject,
              notes: `Automatically revoked ${sessionsActuallyRevokedIds.length} sessions due to exceeding session limit.`
            })
          }
        }
      }
    }

    return {
      devicesRemovedCount,
      sessionsRevokedCount,
      deviceLimitApplied,
      sessionLimitApplied
    }
  }

  // Helper method to get all session IDs for a specific device of a user
  private async getAllSessionsForDevice(userId: number, deviceId: number): Promise<string[]> {
    const userSessionIds = await this.redisService.smembers(`${REDIS_KEY_PREFIX.USER_SESSIONS}${userId}`)
    const deviceSessions: string[] = []
    for (const sessionId of userSessionIds) {
      const sessionDeviceId = await this.redisService.hget(
        `${REDIS_KEY_PREFIX.SESSION_DETAILS}${sessionId}`,
        'deviceId'
      )
      if (sessionDeviceId && parseInt(sessionDeviceId, 10) === deviceId) {
        deviceSessions.push(sessionId)
      }
    }
    return deviceSessions
  }
}
