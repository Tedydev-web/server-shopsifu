import { Injectable, Logger, HttpStatus } from '@nestjs/common'
import { BaseAuthService } from './base-auth.service'
import { REDIS_KEY_PREFIX } from 'src/shared/constants/redis.constants'
import {
  RevokeSessionsBodyDTO,
  DeviceWithSessionsSchema,
  NestedSessionSchema,
  GetSessionsByDeviceQueryDTO
} from '../dtos/session-management.dto'
import { z } from 'zod'
import { UAParser } from 'ua-parser-js'
import { Device } from '@prisma/client'
import { ApiException } from 'src/shared/exceptions/api.exception'
import { I18nContext } from 'nestjs-i18n'
import { AuditLogStatus, AuditLogData } from 'src/routes/audit-log/audit-log.service'
import { Prisma } from '@prisma/client'
import { PaginatedResponseType, createPaginatedResponse } from 'src/shared/models/pagination.model'
import { SessionNotFoundException } from '../auth.error'
import envConfig from 'src/shared/config'
import { DeviceNotFoundForUserException } from '../auth.error'

type DeviceWithSessionsType = z.infer<typeof DeviceWithSessionsSchema>
type NestedSessionType = z.infer<typeof NestedSessionSchema>

@Injectable()
export class SessionManagementService extends BaseAuthService {
  private readonly sessionManagementLogger = new Logger(SessionManagementService.name)

  private _normalizeDeviceType(
    parsedDeviceType?: string,
    osName?: string,
    browserName?: string
  ): DeviceWithSessionsType['type'] {
    switch (parsedDeviceType) {
      case 'console':
      case 'mobile':
      case 'tablet':
      case 'wearable':
        return parsedDeviceType
      case 'smarttv':
        return 'tv'
      default:
        if (osName && browserName && !parsedDeviceType) {
          return 'desktop'
        }
        return 'unknown'
    }
  }

  async getActiveSessions(
    userId: number,
    currentSessionIdFromRequest: string,
    currentDeviceIdFromRequest: number,
    query: GetSessionsByDeviceQueryDTO
  ): Promise<PaginatedResponseType<DeviceWithSessionsType>> {
    this.sessionManagementLogger.debug(
      `Fetching active sessions grouped by device for user ${userId}. Query: ${JSON.stringify(query)}`
    )

    const { page = 1, limit = 10, sortBy = 'lastSeenAt', sortOrder = 'desc' } = query

    const skip = (page - 1) * limit
    const take = limit

    let orderByClause: Prisma.DeviceOrderByWithRelationInput = {}
    if (sortBy === 'lastSeenAt') {
      orderByClause = { lastActive: sortOrder }
    } else if (sortBy === 'firstSeenAt') {
      orderByClause = { createdAt: sortOrder }
    } else if (sortBy === 'name') {
      orderByClause = { name: sortOrder }
    }

    const dbDevices = await this.prismaService.device.findMany({
      where: { userId, isActive: true },
      orderBy: orderByClause,
      skip,
      take
    })

    const totalDevices = await this.prismaService.device.count({
      where: { userId, isActive: true }
    })

    if (dbDevices.length === 0) {
      return createPaginatedResponse([], totalDevices, { page, limit, sortBy, sortOrder })
    }

    const devicesWithSessions: DeviceWithSessionsType[] = []

    for (const dbDevice of dbDevices) {
      const deviceSessionIds = await this.redisService.smembers(`${REDIS_KEY_PREFIX.DEVICE_SESSIONS}${dbDevice.id}`)

      const nestedSessions: NestedSessionType[] = []
      if (deviceSessionIds.length > 0) {
        const sessionDetailsPipeline = this.redisService.client.pipeline()
        deviceSessionIds.forEach((sid) => {
          sessionDetailsPipeline.hgetall(`${REDIS_KEY_PREFIX.SESSION_DETAILS}${sid}`)
        })
        const redisResults = await sessionDetailsPipeline.exec()

        if (redisResults) {
          for (let i = 0; i < redisResults.length; i++) {
            const pipelineItem = redisResults[i]
            if (pipelineItem && !pipelineItem[0] && pipelineItem[1]) {
              const sessionData = pipelineItem[1] as Record<string, string>

              if (
                !sessionData.createdAt ||
                !sessionData.lastActiveAt ||
                parseInt(sessionData.userId, 10) !== userId ||
                parseInt(sessionData.deviceId, 10) !== dbDevice.id
              ) {
                this.sessionManagementLogger.warn(
                  `Session ${deviceSessionIds[i]} has missing/invalid data or mismatch. Skipping. ` +
                    `Expected userId: ${userId}, Actual userId: ${sessionData.userId}. ` +
                    `Expected deviceId: ${dbDevice.id}, Actual deviceId: ${sessionData.deviceId}. ` +
                    `SessionData: ${JSON.stringify(sessionData)}`
                )
                continue
              }

              let validIpAddress: string | null = null
              if (sessionData.ipAddress && sessionData.ipAddress.trim() !== '') {
                try {
                  z.string().ip().parse(sessionData.ipAddress)
                  validIpAddress = sessionData.ipAddress
                } catch (error) {
                  this.sessionManagementLogger.error(
                    `Error parsing IP address for session ${deviceSessionIds[i]}:`,
                    error
                  )
                  this.sessionManagementLogger.warn(
                    `Session ${deviceSessionIds[i]} has an invalid IP address format ('${sessionData.ipAddress}'). Setting to null.`
                  )
                }
              }

              const locationInfo = validIpAddress ? this.geolocationService.lookup(validIpAddress) : null
              const locationString = locationInfo
                ? `${locationInfo.city || 'Unknown City'}, ${locationInfo.country || 'Unknown Country'}`
                : 'Location unknown'

              nestedSessions.push({
                sessionId: deviceSessionIds[i],
                ipAddress: validIpAddress,
                location: locationString,
                loggedInAt: new Date(sessionData.createdAt).toISOString(),
                lastActiveAt: new Date(sessionData.lastActiveAt).toISOString(),
                isCurrentSession: deviceSessionIds[i] === currentSessionIdFromRequest
              })
            }
          }
        }
        nestedSessions.sort((a, b) => {
          if (a.isCurrentSession) return -1
          if (b.isCurrentSession) return 1
          return new Date(b.lastActiveAt).getTime() - new Date(a.lastActiveAt).getTime()
        })
      }

      const uaParser = new UAParser(dbDevice.userAgent)
      const browser = uaParser.getBrowser()
      const os = uaParser.getOS()
      const parsedDeviceType = uaParser.getDevice().type
      const normalizedDeviceType = this._normalizeDeviceType(parsedDeviceType, os.name, browser.name)

      devicesWithSessions.push({
        id: dbDevice.id,
        name: dbDevice.name,
        type: normalizedDeviceType,
        os: os.name && os.version ? `${os.name} ${os.version}` : os.name || null,
        browser: browser.name && browser.version ? `${browser.name} ${browser.version}` : browser.name || null,
        firstSeenAt: dbDevice.createdAt.toISOString(),
        lastSeenAt: dbDevice.lastActive.toISOString(),
        isTrusted: dbDevice.isTrusted,
        isCurrentDevice: dbDevice.id === currentDeviceIdFromRequest,
        sessions: nestedSessions
      })
    }

    return createPaginatedResponse(devicesWithSessions, totalDevices, { page, limit, sortBy, sortOrder })
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
      throw new ApiException(HttpStatus.FORBIDDEN, 'ForbiddenOperation', 'Error.Auth.Session.CannotRevokeCurrent')
    }

    const sessionDetails = await this.redisService.hgetall(`${REDIS_KEY_PREFIX.SESSION_DETAILS}${sessionIdToRevoke}`)
    const sessionOwnerId = sessionDetails?.userId ? parseInt(sessionDetails.userId, 10) : null

    if (!sessionOwnerId || sessionOwnerId !== userId) {
      this.sessionManagementLogger.warn(
        `User ${userId} attempt to revoke session ${sessionIdToRevoke} not belonging to them (owner: ${sessionOwnerId}) or session details missing. Reason: ${revokeReason}`
      )
      throw SessionNotFoundException
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

  async updateDeviceName(userId: number, deviceId: number, name: string): Promise<{ message: string }> {
    const device = await this.prismaService.device.findUnique({ where: { id: deviceId } })
    if (!device || device.userId !== userId) {
      throw new ApiException(HttpStatus.NOT_FOUND, 'DEVICE_NOT_FOUND', 'Error.Auth.Device.NotFound')
    }

    await this.prismaService.device.update({
      where: { id: deviceId },
      data: { name }
    })

    await this.auditLogService.record({
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

  async untrustManagedDevice(
    userId: number,
    deviceId: number,
    currentSessionIdPerformingAction?: string
  ): Promise<{ message: string }> {
    const device = await this.prismaService.device.findUnique({ where: { id: deviceId } })
    if (!device || device.userId !== userId) {
      throw new ApiException(HttpStatus.NOT_FOUND, 'DEVICE_NOT_FOUND', 'Error.Auth.Device.NotFound')
    }

    if (!device.isTrusted) {
      this.sessionManagementLogger.log(`Device ${deviceId} is already untrusted for user ${userId}. No action needed.`)
      const message = await this.i18nService.translate('Auth.Device.AlreadyUntrusted', {
        lang: I18nContext.current()?.lang,
        defaultValue: 'Device is already untrusted.'
      })
      return { message }
    }

    await this.prismaService.device.update({
      where: { id: deviceId },
      data: { isTrusted: false }
    })

    const sessionsForDevice = await this.getAllSessionsForDevice(userId, deviceId)
    let revokedCount = 0
    if (sessionsForDevice.length > 0) {
      this.sessionManagementLogger.log(
        `Found ${sessionsForDevice.length} sessions for device ${deviceId} to potentially revoke after untrusting.`
      )
      for (const sessionIdToRevoke of sessionsForDevice) {
        if (currentSessionIdPerformingAction && sessionIdToRevoke === currentSessionIdPerformingAction) {
          this.sessionManagementLogger.warn(
            `Skipping current session ${currentSessionIdPerformingAction} on device ${deviceId} during untrust operation.`
          )
          continue
        }
        try {
          await this.tokenService.invalidateSession(sessionIdToRevoke, 'DEVICE_UNTRUSTED_SESSIONS_REVOKED')
          revokedCount++
        } catch (error) {
          this.sessionManagementLogger.error(
            `Failed to revoke session ${sessionIdToRevoke} for device ${deviceId} during untrust operation:`,
            error
          )
        }
      }
      this.sessionManagementLogger.log(`Revoked ${revokedCount} sessions for device ${deviceId} after untrusting.`)
    }

    await this.auditLogService.record({
      action: 'DEVICE_UNTRUST_MANAGED',
      userId,
      entity: 'Device',
      entityId: deviceId,
      status: AuditLogStatus.SUCCESS,
      details: {
        deviceUserAgent: device.userAgent,
        sessionsRevoked: revokedCount
      } as Prisma.JsonObject
    })

    const message = await this.i18nService.translate('Auth.Device.Untrusted', { lang: I18nContext.current()?.lang })
    return { message }
  }

  async logoutFromManagedDevice(
    userId: number,
    deviceIdToLogout: number,
    actionPerformer: { userId: number; ipAddress?: string; userAgent?: string }
  ): Promise<{ message: string }> {
    this.sessionManagementLogger.debug(
      `User ${actionPerformer.userId} attempting to logout all sessions for device ${deviceIdToLogout} (owned by user ${userId}).`
    )

    const auditEntry: Partial<AuditLogData> = {
      action: 'LOGOUT_FROM_MANAGED_DEVICE_ATTEMPT',
      entity: 'Device',
      entityId: deviceIdToLogout,
      userId: actionPerformer.userId,
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

    return this.trustManagedDevice(userId, deviceId)
  }

  async revokeMultipleSessions(
    userId: number,
    currentSessionId: string,
    currentDeviceId: number,
    body: RevokeSessionsBodyDTO
  ): Promise<{ message: string; requiresPasswordReverification?: boolean }> {
    this.sessionManagementLogger.debug(
      `User ${userId} attempting to revoke multiple sessions. Current session: ${currentSessionId}, Current device: ${currentDeviceId}, Body: ${JSON.stringify(
        body
      )}`
    )
    const { sessionIds, deviceIds, revokeAll, untrustDevices } = body
    let totalRevokedCount = 0
    let devicesUntrustedCount = 0
    let currentDeviceUntrustedInThisOperation = false
    const auditDetails: Prisma.JsonObject = { requestedBody: body as unknown as Prisma.JsonObject }

    if (revokeAll) {
      this.sessionManagementLogger.log(
        `Processing revokeAll for user ${userId}. Current session: ${currentSessionId}, Current device: ${currentDeviceId}. Untrust devices: ${untrustDevices}`
      )
      const allUserSessionIds = await this.redisService.smembers(`${REDIS_KEY_PREFIX.USER_SESSIONS}${userId}`)
      const distinctDeviceIdsFromSessions = new Set<number>()

      for (const sessionIdToRevoke of allUserSessionIds) {
        if (sessionIdToRevoke === currentSessionId) {
          this.sessionManagementLogger.verbose(
            `revokeAll: Skipping current session ${currentSessionId} from immediate revocation.`
          )
          const currentSessionDetails = await this.redisService.hgetall(
            `${REDIS_KEY_PREFIX.SESSION_DETAILS}${currentSessionId}`
          )
          const cDeviceId = currentSessionDetails?.deviceId ? parseInt(currentSessionDetails.deviceId, 10) : null
          if (cDeviceId) distinctDeviceIdsFromSessions.add(cDeviceId)
          continue
        }

        const sessionDetails = await this.redisService.hgetall(
          `${REDIS_KEY_PREFIX.SESSION_DETAILS}${sessionIdToRevoke}`
        )
        const sessionDeviceId = sessionDetails?.deviceId ? parseInt(sessionDetails.deviceId, 10) : null

        try {
          await this.tokenService.invalidateSession(sessionIdToRevoke, 'REVOKE_ALL_REQUESTED')
          totalRevokedCount++
          if (sessionDeviceId) {
            distinctDeviceIdsFromSessions.add(sessionDeviceId)
          }
        } catch (error) {
          this.sessionManagementLogger.error(
            `Failed to revoke session ${sessionIdToRevoke} for user ${userId} during revokeAll:`,
            error
          )
        }
      }
      auditDetails.sessionsRevokedByRevokeAll = totalRevokedCount

      if (untrustDevices) {
        this.sessionManagementLogger.log(
          `revokeAll: Untrusting devices for user ${userId}. Devices from sessions: ${Array.from(distinctDeviceIdsFromSessions).join(', ')}. Current device to also untrust: ${currentDeviceId}`
        )
        distinctDeviceIdsFromSessions.add(currentDeviceId)

        for (const deviceIdToUntrust of distinctDeviceIdsFromSessions) {
          const device = await this.deviceService.findDeviceById(deviceIdToUntrust)
          if (device && device.userId === userId && device.isTrusted) {
            try {
              await this.deviceService.updateDevice(deviceIdToUntrust, { isTrusted: false })
              devicesUntrustedCount++
              this.sessionManagementLogger.log(
                `Device ${deviceIdToUntrust} untrusted for user ${userId} due to revokeAll.`
              )
              if (deviceIdToUntrust === currentDeviceId) {
                currentDeviceUntrustedInThisOperation = true
                this.sessionManagementLogger.verbose(`revokeAll: Current device ${currentDeviceId} was untrusted.`)
              }
            } catch (error) {
              this.sessionManagementLogger.error(
                `Failed to untrust device ${deviceIdToUntrust} for user ${userId} during revokeAll:`,
                error
              )
            }
          } else if (device && device.userId === userId && !device.isTrusted && deviceIdToUntrust === currentDeviceId) {
            currentDeviceUntrustedInThisOperation = true
            this.sessionManagementLogger.verbose(
              `revokeAll: Current device ${currentDeviceId} was already untrusted but included in untrust scope.`
            )
          }
        }
        auditDetails.devicesUntrustedByRevokeAll = devicesUntrustedCount
      }
    } else if (sessionIds && sessionIds.length > 0) {
      this.sessionManagementLogger.log(`Revoking specific sessions for user ${userId}: ${sessionIds.join(', ')}`)

      for (const sessionIdToRevoke of sessionIds) {
        if (sessionIdToRevoke === currentSessionId) {
          this.sessionManagementLogger.warn(
            `User ${userId} attempted to revoke current session ${currentSessionId} via sessionIds list. Skipping.`
          )
          continue
        }
        try {
          await this.revokeSessionInternal(userId, sessionIdToRevoke, currentSessionId, 'BULK_REVOKE_SESSION_LIST')
          totalRevokedCount++
        } catch (error) {
          this.sessionManagementLogger.error(
            `Failed to revoke session ${sessionIdToRevoke} for user ${userId} during sessionIds list operation:`,
            error
          )
        }
      }
      auditDetails.sessionsRevokedByList = totalRevokedCount
    } else if (deviceIds && deviceIds.length > 0) {
      this.sessionManagementLogger.log(
        `Revoking sessions for devices of user ${userId}: ${deviceIds.join(', ')}. Untrust devices: ${untrustDevices}`
      )
      for (const deviceId of deviceIds) {
        const device = await this.deviceService.findDeviceById(deviceId)
        if (!device || device.userId !== userId) {
          this.sessionManagementLogger.warn(`Device ${deviceId} not found or not owned by user ${userId}. Skipping.`)
          continue
        }

        const sessionsForDevice = await this.getAllSessionsForDevice(userId, deviceId)
        for (const sessionIdToRevoke of sessionsForDevice) {
          if (sessionIdToRevoke === currentSessionId) {
            this.sessionManagementLogger.verbose(
              `Revoke by deviceIds: Skipping current session ${currentSessionId} on device ${deviceId}.`
            )

            continue
          }
          try {
            await this.revokeSessionInternal(userId, sessionIdToRevoke, currentSessionId, 'BULK_REVOKE_DEVICE_SESSIONS')
            totalRevokedCount++
          } catch (error) {
            this.sessionManagementLogger.error(
              `Failed to revoke session ${sessionIdToRevoke} for device ${deviceId} (user ${userId}) during deviceIds list operation:`,
              error
            )
          }
        }

        if (untrustDevices && device.isTrusted) {
          try {
            await this.deviceService.updateDevice(deviceId, { isTrusted: false })
            devicesUntrustedCount++
            this.sessionManagementLogger.log(`Device ${deviceId} untrusted for user ${userId} due to deviceIds list.`)
            if (deviceId === currentDeviceId) {
              currentDeviceUntrustedInThisOperation = true
              this.sessionManagementLogger.verbose(
                `Revoke by deviceIds: Current device ${currentDeviceId} was untrusted.`
              )
            }
          } catch (error) {
            this.sessionManagementLogger.error(
              `Failed to untrust device ${deviceId} for user ${userId} during deviceIds list operation:`,
              error
            )
          }
        } else if (untrustDevices && !device.isTrusted && deviceId === currentDeviceId) {
          currentDeviceUntrustedInThisOperation = true
          this.sessionManagementLogger.verbose(
            `Revoke by deviceIds: Current device ${currentDeviceId} was already untrusted but included in untrust scope.`
          )
        }
      }
      auditDetails.sessionsRevokedByDeviceList = totalRevokedCount
      auditDetails.devicesUntrustedByDeviceList = devicesUntrustedCount
    } else {
      throw new ApiException(HttpStatus.BAD_REQUEST, 'InvalidOperation', 'Error.Auth.Session.InvalidRevokeOperation')
    }

    if (currentDeviceUntrustedInThisOperation) {
      this.sessionManagementLogger.log(
        `Current device ${currentDeviceId} for user ${userId} was untrusted (or confirmed untrusted) in this operation. Session ${currentSessionId} will require password reverification.`
      )
      await this.redisService.hset(
        `${REDIS_KEY_PREFIX.SESSION_DETAILS}${currentSessionId}`,
        'requiresPasswordReverification',
        'true'
      )
      auditDetails.currentSessionRequiresReverification = true

      await this.redisService.hset(`${REDIS_KEY_PREFIX.SESSION_DETAILS}${currentSessionId}`, 'isTrusted', 'false')
      this.sessionManagementLogger.verbose(
        `Updated 'isTrusted' to false in Redis for current session ${currentSessionId}.`
      )
    }

    if (totalRevokedCount === 0 && devicesUntrustedCount === 0 && !currentDeviceUntrustedInThisOperation) {
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
    return { message, requiresPasswordReverification: currentDeviceUntrustedInThisOperation }
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

    if (maxDevices > 0) {
      const userDevices = await this.prismaService.device.findMany({
        where: { userId, isActive: true },
        orderBy: { lastActive: 'asc' }
      })

      if (userDevices.length > maxDevices) {
        deviceLimitApplied = true
        const devicesToPotentiallyRemove = userDevices.filter((d) => d.id !== currentDeviceIdToExclude)
        let numDevicesToRemove =
          devicesToPotentiallyRemove.length - (maxDevices - (userDevices.length - devicesToPotentiallyRemove.length))

        if (numDevicesToRemove > 0) {
          this.sessionManagementLogger.log(
            `User ${userId} has ${userDevices.length} active devices, exceeding limit of ${maxDevices}. Attempting to remove ${numDevicesToRemove} devices.`
          )

          const sortedDevicesToConsider = devicesToPotentiallyRemove.sort((a, b) => {
            if (a.isTrusted !== b.isTrusted) {
              return a.isTrusted ? 1 : -1
            }
            return new Date(a.lastActive).getTime() - new Date(b.lastActive).getTime()
          })

          const devicesActuallyRemoved: Device[] = []
          for (const device of sortedDevicesToConsider) {
            if (numDevicesToRemove <= 0) break

            this.sessionManagementLogger.log(
              `Removing device ${device.id} (trusted: ${device.isTrusted}, lastActive: ${device.lastActive.toISOString()}) for user ${userId} due to device limit.`
            )

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
                isDeviceTrusted: device?.isTrusted || false
              })
            }
          }

          sessionDetailsList.sort((a, b) => {
            if (a.isDeviceTrusted !== b.isDeviceTrusted) {
              return a.isDeviceTrusted ? 1 : -1
            }
            return a.lastActiveAt.getTime() - b.lastActiveAt.getTime()
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

  async debugGetRawSessionsForDevice(deviceId: number, userId: number) {
    this.sessionManagementLogger.debug(
      `[DEBUG] Attempting to fetch raw sessions for deviceId: ${deviceId}, userId: ${userId}`
    )
    const deviceSessionsKey = `${REDIS_KEY_PREFIX.DEVICE_SESSIONS}${deviceId}`
    const sessionIds = await this.redisService.smembers(deviceSessionsKey)

    if (!sessionIds || sessionIds.length === 0) {
      this.sessionManagementLogger.debug(
        `[DEBUG] No session IDs found for deviceId: ${deviceId} in key ${deviceSessionsKey}`
      )
      return { deviceId, userId, message: 'No sessions found for this device.', sessions: [] }
    }

    this.sessionManagementLogger.debug(`[DEBUG] Found session IDs for deviceId ${deviceId}: ${sessionIds.join(', ')}`)

    const detailedSessions: Array<Record<string, any> & { sessionId: string }> = []
    for (const sessionId of sessionIds) {
      const sessionDetailsKey = `${REDIS_KEY_PREFIX.SESSION_DETAILS}${sessionId}`
      const sessionDetails = await this.redisService.hgetall(sessionDetailsKey)
      if (sessionDetails && Object.keys(sessionDetails).length > 0) {
        this.sessionManagementLogger.debug(
          `[DEBUG] Details for session ${sessionId}: ${JSON.stringify(sessionDetails)}`
        )

        if (sessionDetails.userId && Number(sessionDetails.userId) === userId) {
          detailedSessions.push({ sessionId, ...sessionDetails })
        } else {
          this.sessionManagementLogger.warn(
            `[DEBUG] Session ${sessionId} for device ${deviceId} does NOT belong to user ${userId} (found user ${sessionDetails.userId}). Skipping.`
          )
        }
      } else {
        this.sessionManagementLogger.warn(
          `[DEBUG] No details found for session ${sessionId} at key ${sessionDetailsKey}`
        )
      }
    }
    this.sessionManagementLogger.debug(
      `[DEBUG] Returning ${detailedSessions.length} detailed sessions for deviceId: ${deviceId}, userId: ${userId}`
    )
    return { deviceId, userId, sessions: detailedSessions }
  }
}
