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
import { DeviceNotFoundForUserException } from '../auth.error'

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
    this.sessionManagementLogger.debug(
      `User ${userId} attempting to revoke session ${sessionIdToRevoke}. Current session: ${currentSessionId}`
    )
    await this.revokeSessionInternal(userId, sessionIdToRevoke, currentSessionId, 'SINGLE_REVOKE_REQUEST')
    const message = await this.i18nService.translate('Auth.Session.RevokedSuccessfully', {
      lang: I18nContext.current()?.lang
    })
    return { message }
  }

  private async revokeSessionInternal(
    userId: number,
    sessionIdToRevoke: string,
    currentSessionId: string,
    revokeReason: string = 'INTERNAL_REQUEST'
  ): Promise<void> {
    if (sessionIdToRevoke === currentSessionId) {
      this.sessionManagementLogger.warn(
        `Attempt to revoke current session ${currentSessionId} for user ${userId} via internal call. Reason: ${revokeReason}. This is generally disallowed directly.`
      )
      // Depending on the revokeReason or specific logic, you might throw an error here
      // For now, we prevent direct revocation of current session through this internal method
      // to align with the general principle that users logout of current session via /logout
      throw new ApiException(HttpStatus.FORBIDDEN, 'ForbiddenOperation', 'Error.Auth.Session.CannotRevokeCurrent')
    }

    // Check if session belongs to the user before revoking
    const sessionDetails = await this.redisService.hgetall(`${REDIS_KEY_PREFIX.SESSION_DETAILS}${sessionIdToRevoke}`)
    const sessionOwnerId = sessionDetails?.userId ? parseInt(sessionDetails.userId, 10) : null

    if (!sessionOwnerId || sessionOwnerId !== userId) {
      this.sessionManagementLogger.warn(
        `User ${userId} attempt to revoke session ${sessionIdToRevoke} not belonging to them (owner: ${sessionOwnerId}) or session details missing. Reason: ${revokeReason}`
      )
      throw SessionNotFoundException // Or a more specific "permission denied" error
    }

    await this.tokenService.invalidateSession(sessionIdToRevoke, `USER_REQUEST_REVOKE_SESSION (${revokeReason})`)
    this.sessionManagementLogger.log(
      `Session ${sessionIdToRevoke} for user ${userId} revoked successfully. Reason: ${revokeReason}`
    )

    await this.auditLogService.recordAsync({
      action: 'REVOKE_SESSION_INTERNAL_SUCCESS',
      userId,
      status: AuditLogStatus.SUCCESS,
      entity: 'Session',
      entityId: sessionIdToRevoke,
      details: { reason: revokeReason } as Prisma.JsonObject
    })
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
    this.sessionManagementLogger.debug(`Attempting to trust managed device ${deviceId} for user ${userId}`)

    const auditEntry: Partial<AuditLogData> = {
      action: 'TRUST_MANAGED_DEVICE_ATTEMPT',
      entity: 'Device',
      entityId: deviceId,
      userId,
      status: AuditLogStatus.FAILURE
    }

    const device = await this.deviceService.findDeviceById(deviceId)
    if (!device || device.userId !== userId) {
      auditEntry.errorMessage = 'Device not found or does not belong to user.'
      await this.auditLogService.recordAsync(auditEntry as AuditLogData)
      throw DeviceNotFoundForUserException
    }

    if (device.isTrusted) {
      const message = await this.i18nService.translate('Auth.Device.AlreadyTrusted', {
        lang: I18nContext.current()?.lang
      })
      auditEntry.status = AuditLogStatus.SUCCESS
      auditEntry.action = 'TRUST_MANAGED_DEVICE_ALREADY_TRUSTED'
      auditEntry.notes = 'Device was already trusted.'
      await this.auditLogService.recordAsync(auditEntry as AuditLogData)
      return { message }
    }

    await this.deviceService.updateDevice(deviceId, { isTrusted: true })

    auditEntry.status = AuditLogStatus.SUCCESS
    auditEntry.action = 'TRUST_MANAGED_DEVICE_SUCCESS'
    await this.auditLogService.recordAsync(auditEntry as AuditLogData)

    const message = await this.i18nService.translate('Auth.Device.Trusted', { lang: I18nContext.current()?.lang })
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

    const message = await this.i18nService.translate('Auth.Device.Untrusted', { lang: I18nContext.current()?.lang })
    return { message }
  }

  async logoutFromManagedDevice(
    userId: number, // User whose device is being logged out
    deviceIdToLogout: number,
    actionPerformer: { userId: number; ipAddress?: string; userAgent?: string } // User performing the action
  ): Promise<{ message: string }> {
    this.sessionManagementLogger.debug(
      `User ${actionPerformer.userId} attempting to logout all sessions for device ${deviceIdToLogout} (owned by user ${userId}).`
    )

    const auditEntry: Partial<AuditLogData> = {
      action: 'LOGOUT_FROM_MANAGED_DEVICE_ATTEMPT',
      entity: 'Device',
      entityId: deviceIdToLogout,
      userId: actionPerformer.userId, // Logged as the user performing the action
      status: AuditLogStatus.FAILURE,
      details: {
        targetUserId: userId,
        targetDeviceId: deviceIdToLogout
      } as Prisma.JsonObject
    }

    if (actionPerformer.ipAddress) auditEntry.ipAddress = actionPerformer.ipAddress
    if (actionPerformer.userAgent) auditEntry.userAgent = actionPerformer.userAgent

    const deviceToLogout = await this.deviceService.findDeviceById(deviceIdToLogout)

    if (!deviceToLogout || deviceToLogout.userId !== userId) {
      auditEntry.errorMessage = 'Device not found or does not belong to the specified target user.'
      await this.auditLogService.recordAsync(auditEntry as AuditLogData)
      throw DeviceNotFoundForUserException
    }

    // Invalidate all sessions associated with this device ID
    const sessionsRevokedCount = await this.tokenService.invalidateSessionsByDeviceId(
      deviceIdToLogout,
      'MANAGED_DEVICE_LOGOUT'
    )

    auditEntry.status = AuditLogStatus.SUCCESS
    auditEntry.action = 'LOGOUT_FROM_MANAGED_DEVICE_SUCCESS'
    ;(auditEntry.details as Prisma.JsonObject).sessionsRevokedCount = sessionsRevokedCount
    await this.auditLogService.recordAsync(auditEntry as AuditLogData)

    const message = await this.i18nService.translate('Auth.Device.LogoutSpecificSuccess', {
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
    this.sessionManagementLogger.debug(
      `User ${userId} attempting to revoke multiple sessions. Current session: ${currentSessionId}, Body: ${JSON.stringify(body)}`
    )
    const { sessionIds, deviceIds, revokeAll } = body
    let totalRevokedCount = 0
    let devicesUntrustedCount = 0
    const auditDetails: Prisma.JsonObject = { requestedBody: body as unknown as Prisma.JsonObject }

    if (sessionIds && sessionIds.length > 0) {
      this.sessionManagementLogger.log(`Revoking specific sessions for user ${userId}: ${sessionIds.join(', ')}`)
      for (const sessionIdToRevoke of sessionIds) {
        if (sessionIdToRevoke === currentSessionId) {
          this.sessionManagementLogger.warn(
            `User ${userId} attempted to revoke current session ${currentSessionId} via bulk. Skipping.`
          )
          continue
        }
        try {
          await this.revokeSessionInternal(userId, sessionIdToRevoke, currentSessionId, 'BULK_REVOKE_SESSION_LIST')
          totalRevokedCount++
        } catch (error) {
          this.sessionManagementLogger.error(
            `Failed to revoke session ${sessionIdToRevoke} for user ${userId} during bulk operation:`,
            error
          )
          // Optionally collect errors or rethrow if one failure should stop all
        }
      }
      auditDetails.sessionsRevokedByList = totalRevokedCount
    } else if (deviceIds && deviceIds.length > 0) {
      this.sessionManagementLogger.log(`Revoking sessions for devices of user ${userId}: ${deviceIds.join(', ')}`)
      for (const deviceIdToUntrust of deviceIds) {
        const device = await this.deviceService.findDeviceById(deviceIdToUntrust)
        if (!device || device.userId !== userId) {
          this.sessionManagementLogger.warn(
            `Device ${deviceIdToUntrust} not found or not owned by user ${userId}. Skipping.`
          )
          continue
        }

        const revokedForDevice = await this.tokenService.invalidateSessionsByDeviceId(
          deviceIdToUntrust,
          'BULK_REVOKE_DEVICE_SESSIONS'
        )
        totalRevokedCount += revokedForDevice
        // Untrust the device
        if (device.isTrusted) {
          await this.deviceService.updateDevice(deviceIdToUntrust, { isTrusted: false })
          devicesUntrustedCount++
          this.sessionManagementLogger.log(`Device ${deviceIdToUntrust} untrusted for user ${userId}.`)
        }
      }
      auditDetails.sessionsRevokedByDevice = totalRevokedCount
      auditDetails.devicesUntrusted = devicesUntrustedCount
    } else if (revokeAll) {
      this.sessionManagementLogger.log(`Revoking all sessions for user ${userId} except current ${currentSessionId}`)
      const result = await this.tokenService.invalidateAllUserSessions(
        userId,
        'USER_REQUEST_REVOKE_ALL_EXCEPT_CURRENT',
        currentSessionId
      )
      totalRevokedCount = result.invalidatedCount
      auditDetails.allSessionsExceptCurrentRevoked = totalRevokedCount
    } else {
      throw new ApiException(HttpStatus.BAD_REQUEST, 'InvalidOperation', 'Error.Auth.Session.InvalidRevokeOperation')
    }

    if (totalRevokedCount === 0 && devicesUntrustedCount === 0) {
      await this.auditLogService.recordAsync({
        action: 'REVOKE_MULTIPLE_SESSIONS_NO_ACTION',
        userId,
        status: AuditLogStatus.SUCCESS,
        notes: 'No sessions were revoked or devices untrusted based on the criteria.',
        details: auditDetails
      })
      const noSessionsMessage = await this.i18nService.translate('error.Auth.Session.NoSessionsToRevoke', {
        lang: I18nContext.current()?.lang
      })
      return { message: noSessionsMessage }
    }

    await this.auditLogService.recordAsync({
      action: 'REVOKE_MULTIPLE_SESSIONS_SUCCESS',
      userId,
      status: AuditLogStatus.SUCCESS,
      details: auditDetails
    })

    const message = await this.i18nService.translate('error.Auth.Session.RevokedSuccessfullyCount', {
      lang: I18nContext.current()?.lang,
      args: { count: totalRevokedCount }
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
      `Enforcing session/device limits for user ${userId}. Exclude session: ${currentSessionIdToExclude}, Exclude device: ${currentDeviceIdToExclude}`
    )
    let devicesRemovedCount = 0
    let sessionsRevokedByDeviceLimit = 0
    let sessionsRevokedBySessionLimit = 0
    let deviceLimitApplied = false
    let sessionLimitApplied = false

    const maxDevices = envConfig.MAX_DEVICES_PER_USER
    const maxSessions = envConfig.MAX_ACTIVE_SESSIONS_PER_USER

    // --- Device Limit Enforcement ---
    if (maxDevices > 0) {
      const userDevices = await this.prismaService.device.findMany({
        where: { userId, isActive: true },
        orderBy: { lastActive: 'asc' } // Oldest first
      })

      if (userDevices.length > maxDevices) {
        deviceLimitApplied = true
        const devicesToPotentiallyRemove = userDevices.filter((d) => d.id !== currentDeviceIdToExclude)
        let numDevicesToRemove =
          devicesToPotentiallyRemove.length - (maxDevices - (userDevices.length - devicesToPotentiallyRemove.length))
        //This calculation ensures we only consider removable devices to reach the target count.

        if (numDevicesToRemove > 0) {
          this.sessionManagementLogger.log(
            `User ${userId} has ${userDevices.length} active devices, exceeding limit of ${maxDevices}. Attempting to remove ${numDevicesToRemove} devices.`
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
                sessionsRevokedByDeviceLimit++
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
                maxDevices,
                currentDeviceCount: userDevices.length,
                removedDevices: devicesActuallyRemoved.map((d) => ({
                  id: d.id,
                  name: d.name,
                  isTrusted: d.isTrusted,
                  lastActive: d.lastActive.toISOString()
                })),
                sessionsRevokedRelatedToDevices: sessionsRevokedByDeviceLimit
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
              sessionsRevokedBySessionLimit++
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
      sessionsRevokedCount: sessionsRevokedByDeviceLimit + sessionsRevokedBySessionLimit,
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
