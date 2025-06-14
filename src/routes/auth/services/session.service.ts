import { Injectable, Logger, Inject } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { I18nService } from 'nestjs-i18n'
import { Response } from 'express'
import { z } from 'zod'

import { PrismaService } from 'src/shared/providers/prisma/prisma.service'
import { RedisService } from 'src/shared/providers/redis/redis.service'
import { RedisKeyManager } from 'src/shared/providers/redis/redis-keys.utils'
import { GeolocationService, GeoLocationResult } from 'src/shared/services/geolocation.service'
import { EmailService } from 'src/shared/services/email.service'
import { UserAgentService } from '../../../shared/services/user-agent.service'

import { SessionRepository } from 'src/routes/auth/repositories'
import { DeviceRepository } from 'src/shared/repositories/device.repository'

import {
  EMAIL_SERVICE,
  GEOLOCATION_SERVICE,
  USER_AGENT_SERVICE,
  COOKIE_SERVICE,
  REDIS_SERVICE
} from 'src/shared/constants/injection.tokens'

import { AuthError } from 'src/routes/auth/auth.error'
import { ICookieService, ISessionService } from 'src/routes/auth/auth.types'
import { GetGroupedSessionsResponseSchema } from '../dtos/session.dto'
import { I18nTranslations } from 'src/generated/i18n.generated'
import { Device } from '@prisma/client'

type DeviceSessionGroup = z.infer<typeof GetGroupedSessionsResponseSchema.shape.devices.element>

type SafetyAnalysis = {
  shouldExcludeCurrentSession: boolean
  willCauseLogout: boolean
  warningMessage?: string
  requiresConfirmation?: boolean
  autoProtected?: boolean
}

@Injectable()
export class SessionsService implements ISessionService {
  private readonly logger = new Logger(SessionsService.name)

  constructor(
    private readonly i18nService: I18nService<I18nTranslations>,
    private readonly configService: ConfigService,
    private readonly sessionRepository: SessionRepository,
    private readonly deviceRepository: DeviceRepository,
    @Inject(EMAIL_SERVICE) private readonly emailService: EmailService,
    private readonly prismaService: PrismaService,
    @Inject(GEOLOCATION_SERVICE) private readonly geolocationService: GeolocationService,
    @Inject(REDIS_SERVICE) private readonly redisService: RedisService,
    @Inject(USER_AGENT_SERVICE) private readonly userAgentService: UserAgentService,
    @Inject(COOKIE_SERVICE) private readonly cookieService: ICookieService
  ) {}

  async getSessions(
    userId: number,
    currentPage: number = 1,
    itemsPerPage: number = 5,
    currentSessionIdFromToken: string
  ): Promise<any> {
    // Lấy tất cả sessions và devices
    const sessionResult = await this.sessionRepository.findSessionsByUserId(userId, { page: 1, limit: 1000 })
    let devices = await this.deviceRepository.findDevicesByUserId(userId)
    devices = await this.ensureCurrentDeviceIncluded(currentSessionIdFromToken, devices)

    const deviceGroups: DeviceSessionGroup[] = []

    for (const device of devices) {
      const deviceSessions = sessionResult.data.filter((session) => session.deviceId === device.id)
      if (deviceSessions.length === 0) continue

      const currentSessionDetails = await this.sessionRepository.findById(currentSessionIdFromToken)
      const isCurrentDevice = currentSessionDetails?.deviceId === device.id
      const latestSession = deviceSessions[0]
      const deviceInfo = this.userAgentService.parse(latestSession?.userAgent)
      const activeSessionsCount = deviceSessions.filter((s) => s.isActive).length

      // Process location
      let locationResult: GeoLocationResult
      try {
        locationResult = await this.getLocationFromIP(latestSession.ipAddress || '')
      } catch {
        locationResult = { display: 'Unknown Location', timezone: 'Asia/Ho_Chi_Minh' }
      }

      // Process session items
      const sessionItems = await Promise.all(
        deviceSessions.map(async (session) => {
          const sessionInfo = this.userAgentService.parse(session.userAgent)
          const inactiveDuration = session.isActive
            ? null
            : this.calculateInactiveDuration(new Date(session.lastActive))

          let sessionLocationResult: GeoLocationResult
          try {
            sessionLocationResult = await this.getLocationFromIP(session.ipAddress || '')
          } catch {
            sessionLocationResult = { display: 'Unknown Location', timezone: 'Asia/Ho_Chi_Minh' }
          }

          return {
            id: session.id,
            createdAt: new Date(session.createdAt),
            lastActive: new Date(session.lastActive),
            ipAddress: session.ipAddress,
            location: sessionLocationResult?.display || 'Unknown Location',
            browser: sessionInfo.browser,
            browserVersion: sessionInfo.browserVersion,
            app: sessionInfo.app,
            os: sessionInfo.os,
            osVersion: sessionInfo.osVersion,
            deviceType: sessionInfo.deviceType,
            isActive: session.isActive,
            inactiveDuration,
            isCurrentSession: session.id === currentSessionIdFromToken
          }
        })
      )

      deviceGroups.push({
        deviceId: device.id,
        deviceName: deviceInfo.deviceName,
        deviceType: deviceInfo.deviceType,
        os: deviceInfo.os,
        osVersion: deviceInfo.osVersion,
        browser: deviceInfo.browser,
        browserVersion: deviceInfo.browserVersion,
        isDeviceTrusted: device.isTrusted,
        deviceTrustExpiration: device.trustExpiration,
        lastActive: new Date(latestSession.lastActive),
        location: locationResult?.display || 'Unknown Location',
        activeSessionsCount,
        totalSessionsCount: deviceSessions.length,
        isCurrentDevice,
        sessions: sessionItems
      })
    }

    // Sort and paginate
    deviceGroups.sort((a, b) => (b.lastActive?.getTime() || 0) - (a.lastActive?.getTime() || 0))
    const totalItems = deviceGroups.length
    const totalPages = Math.ceil(totalItems / itemsPerPage)
    const startIndex = (currentPage - 1) * itemsPerPage
    const paginatedDeviceGroups = deviceGroups.slice(startIndex, startIndex + itemsPerPage)

    return {
      message: 'auth.success.session.retrieved',
      data: {
        devices: paginatedDeviceGroups,
        meta: { currentPage, itemsPerPage, totalItems, totalPages }
      }
    }
  }

  private async ensureCurrentDeviceIncluded(currentSessionId: string, devices: Device[]): Promise<Device[]> {
    const currentSession = await this.sessionRepository.findById(currentSessionId)
    if (!currentSession) return devices

    const currentDeviceId = currentSession.deviceId
    const hasCurrentDevice = devices.some((d) => d.id === currentDeviceId)

    if (!hasCurrentDevice) {
      const currentDevice = await this.deviceRepository.findById(currentDeviceId)
      if (currentDevice) {
        return [...devices, currentDevice]
      }
    }
    return devices
  }

  private async getLocationFromIP(ip: any): Promise<GeoLocationResult> {
    const ipString = String(ip || '')
    return this.geolocationService.getLocationFromIP(ipString)
  }

  private calculateInactiveDuration(lastActiveDate: Date): string {
    const diffSeconds = Math.round((Date.now() - lastActiveDate.getTime()) / 1000)

    if (diffSeconds < 60) return 'global.error.duration.justNow'

    const diffMinutes = Math.round(diffSeconds / 60)
    if (diffMinutes === 1) return 'global.error.duration.aMinuteAgo'
    if (diffMinutes < 60) return 'global.error.duration.minutesAgo'

    const diffHours = Math.round(diffMinutes / 60)
    if (diffHours === 1) return (this.i18nService as any).t('global.error.duration.anHourAgo')
    if (diffHours < 24)
      return (this.i18nService as any).t('global.error.duration.hoursAgo', { args: { count: diffHours } })

    const diffDays = Math.round(diffHours / 24)
    if (diffDays === 1) return (this.i18nService as any).t('global.error.duration.aDayAgo')
    return (this.i18nService as any).t('global.error.duration.daysAgo', { args: { count: diffDays } })
  }

  private async notifyDeviceTrustChange(
    userId: number,
    deviceId: number,
    action: 'trusted' | 'untrusted'
  ): Promise<void> {
    const user = await this.prismaService.user.findUnique({
      where: { id: userId },
      include: { userProfile: true }
    })
    const device = await this.deviceRepository.findById(deviceId)

    if (user && device) {
      const deviceInfo = this.userAgentService.parse(device.userAgent)
      const details = [
        {
          label: 'email.Email.common.details.device',
          value: `${deviceInfo.browser} on ${deviceInfo.os}`
        },
        {
          label: 'email.Email.common.details.ipAddress',
          value: device.lastKnownIp ?? 'N/A'
        },
        {
          label: 'email.Email.common.details.location',
          value: (await this.getLocationFromIP(device.lastKnownIp ?? '')).display
        }
      ]

      await this.emailService.sendDeviceTrustChangeEmail(user.email, {
        userName: user.userProfile?.username ?? user.email,
        action,
        details
      })
    }
  }

  async revokeItems(
    userId: number,
    options: {
      sessionIds?: string[]
      deviceIds?: number[]
      revokeAllUserSessions?: boolean
      excludeCurrentSession?: boolean
    },
    currentSessionContext: { sessionId?: string; deviceId?: number },
    res?: Response
  ): Promise<{
    message: string
    data: {
      revokedSessionsCount: number
      untrustedDevicesCount: number
      willCauseLogout: boolean
      warningMessage?: string
      requiresConfirmation?: boolean
      autoProtected?: boolean
      shouldExcludeCurrentSession?: boolean
    }
  }> {
    // Step 1: Validate input
    const validation = this.validateRevokeOptions(options)
    if (!validation.isValid) {
      throw AuthError.InvalidRevokeParams()
    }

    // Step 2: Smart analysis
    const analysis = this.analyzeExcludeCurrentSessionLogic(options, currentSessionContext)

    // Step 3: Safety check
    if (analysis.requiresConfirmation) {
      throw AuthError.ActionRequiresConfirmation(analysis.warningMessage || 'Action requires confirmation')
    }

    // Step 4: Execute revocation với smart logic
    const finalOptions = { ...options, excludeCurrentSession: analysis.shouldExcludeCurrentSession }
    const { revokedSessionsCount, untrustedDevicesCount } = await this.executeRevocation(
      userId,
      finalOptions,
      currentSessionContext
    )

    // Step 5: Post-revocation cleanup
    if (revokedSessionsCount > 0) {
      await this.setReverifyFlagForUser(userId)
    }

    const currentSessionRevoked = this.isCurrentSessionRevoked(finalOptions, currentSessionContext)
    if (currentSessionRevoked && res) {
      this.clearCurrentSessionCookies(res)
    }

    // Step 6: Generate response
    let message: string
    if (revokedSessionsCount > 0) {
      message = this.i18nService.t('auth.success.session.revokedCount', { args: { count: revokedSessionsCount } })
    } else {
      // Check if this was due to smart protection
      if (analysis.autoProtected === true || analysis.shouldExcludeCurrentSession === true) {
        message = this.i18nService.t('auth.success.session.autoProtected')
      } else {
        message = this.i18nService.t('auth.success.session.noSessionsToRevoke')
      }
    }

    return {
      message,
      data: {
        revokedSessionsCount,
        untrustedDevicesCount,
        willCauseLogout: analysis.willCauseLogout && currentSessionRevoked,
        warningMessage: analysis.warningMessage,
        requiresConfirmation: analysis.requiresConfirmation
      }
    }
  }

  private analyzeExcludeCurrentSessionLogic(
    options: {
      sessionIds?: string[]
      deviceIds?: number[]
      revokeAllUserSessions?: boolean
      excludeCurrentSession?: boolean
      autoProtected?: boolean
    },
    currentSessionContext: { sessionId?: string; deviceId?: number }
  ): {
    shouldExcludeCurrentSession: boolean
    willCauseLogout: boolean
    warningMessage?: string
    requiresConfirmation?: boolean
    autoProtected?: boolean
  } {
    const { sessionIds, deviceIds, revokeAllUserSessions, excludeCurrentSession } = options
    const { sessionId: currentSessionId, deviceId: currentDeviceId } = currentSessionContext

    // Determine analysis based on revocation type
    if (revokeAllUserSessions) {
      return this.analyzeRevokeAllSessions(excludeCurrentSession)
    } else if (deviceIds?.length) {
      return this.analyzeRevokeDevices(deviceIds, currentDeviceId, excludeCurrentSession)
    } else if (sessionIds?.length) {
      return this.analyzeRevokeSessions(sessionIds, currentSessionId, excludeCurrentSession)
    } else {
      return {
        shouldExcludeCurrentSession: false,
        willCauseLogout: false
      }
    }
  }

  private analyzeRevokeAllSessions(excludeCurrentSession?: boolean): SafetyAnalysis {
    if (excludeCurrentSession !== undefined) {
      return excludeCurrentSession
        ? {
            shouldExcludeCurrentSession: true,
            willCauseLogout: false
          }
        : {
            shouldExcludeCurrentSession: false,
            willCauseLogout: true,
            warningMessage: 'You will be logged out from all sessions including current one.',
            requiresConfirmation: true
          }
    }
    // Smart default: exclude current session for safety
    return {
      shouldExcludeCurrentSession: true,
      willCauseLogout: false,
      autoProtected: true
    }
  }

  private analyzeRevokeDevices(
    deviceIds: number[],
    currentDeviceId?: number,
    excludeCurrentSession?: boolean
  ): SafetyAnalysis {
    const includesCurrentDevice = currentDeviceId && deviceIds.includes(currentDeviceId)

    if (!includesCurrentDevice) {
      return {
        shouldExcludeCurrentSession: false,
        willCauseLogout: false
      }
    }

    if (excludeCurrentSession !== undefined) {
      return excludeCurrentSession
        ? {
            shouldExcludeCurrentSession: true,
            willCauseLogout: false
          }
        : {
            shouldExcludeCurrentSession: false,
            willCauseLogout: true,
            warningMessage: 'You will be logged out by revoking your current device.',
            requiresConfirmation: true
          }
    }
    // Smart default: exclude current device for safety
    return {
      shouldExcludeCurrentSession: true,
      willCauseLogout: false
    }
  }

  private analyzeRevokeSessions(
    sessionIds: string[],
    currentSessionId?: string,
    excludeCurrentSession?: boolean
  ): SafetyAnalysis {
    const includesCurrentSession = currentSessionId && sessionIds.includes(currentSessionId)

    if (!includesCurrentSession) {
      return {
        shouldExcludeCurrentSession: false,
        willCauseLogout: false
      }
    }

    if (excludeCurrentSession !== undefined) {
      return excludeCurrentSession
        ? {
            shouldExcludeCurrentSession: true,
            willCauseLogout: false
          }
        : {
            shouldExcludeCurrentSession: false,
            willCauseLogout: true,
            warningMessage: 'You will be logged out by revoking your current session.',
            requiresConfirmation: true
          }
    }
    // Smart default: exclude current session for safety
    return {
      shouldExcludeCurrentSession: true,
      willCauseLogout: false,
      autoProtected: true
    }
  }

  private async setReverifyFlagForUser(userId: number): Promise<void> {
    const key = RedisKeyManager.getUserReverifyNextLoginKey(userId)
    const ttl = 24 * 60 * 60 // 24 giờ
    await this.redisService.set(key, '1', 'EX', ttl)
  }

  private isCurrentSessionRevoked(
    options: {
      sessionIds?: string[]
      deviceIds?: number[]
      revokeAllUserSessions?: boolean
      excludeCurrentSession?: boolean
    },
    currentSessionContext: { sessionId?: string; deviceId?: number }
  ): boolean {
    const { sessionIds, deviceIds, revokeAllUserSessions, excludeCurrentSession } = options
    const { sessionId: currentSessionId, deviceId: currentDeviceId } = currentSessionContext

    // If excludeCurrentSession = true, don't revoke current session
    if (excludeCurrentSession) return false

    // If revokeAllUserSessions = true and not excluding current session
    if (revokeAllUserSessions) return true

    // Check if current session is in sessionIds list
    if (sessionIds?.length && currentSessionId && sessionIds.includes(currentSessionId)) return true

    // Check if current device is in deviceIds list
    if (deviceIds?.length && currentDeviceId && deviceIds.includes(currentDeviceId)) return true

    return false
  }

  private clearCurrentSessionCookies(res: Response): void {
    // Clear login-related cookies
    this.cookieService.clearTokenCookies(res)
    // Clear SLT cookie if exists
    this.cookieService.clearSltCookie(res)
  }

  private async revokeSingleSession(
    sessionId: string,
    userId: number,
    isLogout: boolean = false
  ): Promise<number | null> {
    const session = await this.sessionRepository.findById(sessionId)
    if (!session || session.userId !== userId) {
      throw AuthError.InsufficientPermissions()
    }

    const { deviceId } = session
    await this.sessionRepository.deleteSession(sessionId)

    // Check if it's the last session on device
    const remainingSessions = await this.sessionRepository.countSessionsByDeviceId(deviceId)
    if (remainingSessions === 0 && !isLogout) {
      await this.deviceRepository.updateDeviceTrustStatus(deviceId, false)
      return deviceId
    }

    return null
  }

  private async revokeDevice(
    deviceId: number,
    userId: number,
    excludeSessionId?: string
  ): Promise<{ revokedSessionsCount: number; untrusted: boolean }> {
    const device = await this.deviceRepository.findById(deviceId)
    if (!device || device.userId !== userId) {
      throw AuthError.DeviceNotFound()
    }

    const { count } = await this.sessionRepository.deleteSessionsByDeviceId(deviceId, excludeSessionId)

    await this.deviceRepository.updateDeviceTrustStatus(deviceId, false)

    return { revokedSessionsCount: count, untrusted: true }
  }

  async invalidateSession(sessionId: string): Promise<void> {
    const key = RedisKeyManager.getInvalidatedSessionsKey()
    await this.redisService.sadd(key, sessionId)

    const sessionTtl = this.configService.get<number>('JWT_REFRESH_EXPIRATION_TIME', 604800) * 1000
    await this.redisService.expire(key, sessionTtl / 1000)

    const session = await this.sessionRepository.findById(sessionId)
    if (!session) {
      return
    }
  }

  async isSessionInvalidated(sessionId: string): Promise<boolean> {
    const key = RedisKeyManager.getInvalidatedSessionsKey()
    const result = await this.redisService.sismember(key, sessionId)
    return result === 1
  }

  async invalidateAllUserSessions(
    userId: number,
    reason?: string,
    sessionIdToExclude?: string
  ): Promise<{ deletedSessionsCount: number; untrustedDeviceIds: number[] }> {
    const { deletedSessionsCount, affectedDeviceIds } = await this.sessionRepository.deleteAllUserSessions(
      userId,
      sessionIdToExclude
    )

    const newlyUntrustedDeviceIds: number[] = []

    if (affectedDeviceIds.length > 0) {
      for (const deviceId of affectedDeviceIds) {
        const remainingSessionsOnDevice = await this.sessionRepository.countSessionsByDeviceId(deviceId)
        if (remainingSessionsOnDevice === 0) {
          await this.deviceRepository.updateDeviceTrustStatus(deviceId, false)
          newlyUntrustedDeviceIds.push(deviceId)
        }
      }
    }

    return { deletedSessionsCount, untrustedDeviceIds: newlyUntrustedDeviceIds }
  }

  private async executeRevocation(
    userId: number,
    options: {
      sessionIds?: string[]
      deviceIds?: number[]
      revokeAllUserSessions?: boolean
      excludeCurrentSession?: boolean
    },
    currentSessionContext: { sessionId?: string; deviceId?: number }
  ): Promise<{ revokedSessionsCount: number; untrustedDevicesCount: number }> {
    let revokedSessionsCount = 0
    const excludeSessionId = options.excludeCurrentSession ? currentSessionContext.sessionId : undefined

    if (options.revokeAllUserSessions) {
      const result = await this.invalidateAllUserSessions(
        userId,
        'User requested revoke all sessions',
        excludeSessionId
      )
      return {
        revokedSessionsCount: result.deletedSessionsCount,
        untrustedDevicesCount: result.untrustedDeviceIds.length
      }
    }

    const untrustedDeviceIds = new Set<number>()

    // Revoke specific sessions
    if (options.sessionIds?.length) {
      for (const sessionId of options.sessionIds) {
        if (sessionId === excludeSessionId) continue
        const untrustedDeviceId = await this.revokeSingleSession(sessionId, userId)
        if (untrustedDeviceId) untrustedDeviceIds.add(untrustedDeviceId)
        revokedSessionsCount++
      }
    }

    // Revoke specific devices
    if (options.deviceIds?.length) {
      for (const deviceId of options.deviceIds) {
        if (deviceId === currentSessionContext.deviceId && options.excludeCurrentSession) continue
        const result = await this.revokeDevice(deviceId, userId, excludeSessionId)
        revokedSessionsCount += result.revokedSessionsCount
        if (result.untrusted) untrustedDeviceIds.add(deviceId)
      }
    }

    return {
      revokedSessionsCount,
      untrustedDevicesCount: untrustedDeviceIds.size
    }
  }

  private validateRevokeOptions(options: {
    sessionIds?: string[]
    deviceIds?: number[]
    revokeAllUserSessions?: boolean
    excludeCurrentSession?: boolean
  }): { isValid: boolean; errors: string[] } {
    const { sessionIds, deviceIds, revokeAllUserSessions } = options
    const errors: string[] = []

    // Must have at least one target
    if (!revokeAllUserSessions && !sessionIds?.length && !deviceIds?.length) {
      errors.push('Must specify at least one of: sessionIds, deviceIds, or revokeAllUserSessions')
    }

    // Cannot specify multiple targets simultaneously
    const targets = [revokeAllUserSessions, sessionIds?.length, deviceIds?.length].filter(Boolean)
    if (targets.length > 1) {
      errors.push('Cannot specify multiple revoke targets simultaneously')
    }

    // Validate formats
    if (sessionIds?.some((id) => !id || typeof id !== 'string' || !id.trim())) {
      errors.push('Invalid session IDs provided')
    }
    if (deviceIds?.some((id) => !Number.isInteger(id) || id <= 0)) {
      errors.push('Invalid device IDs provided')
    }

    return { isValid: errors.length === 0, errors }
  }

  async updateDeviceName(userId: number, deviceId: number, name: string): Promise<void> {
    const device = await this.deviceRepository.findById(deviceId)
    if (!device || device.userId !== userId) {
      throw AuthError.DeviceNotFound()
    }
    await this.deviceRepository.updateDeviceName(deviceId, name)
  }

  async trustCurrentDevice(userId: number, deviceId: number): Promise<void> {
    const device = await this.deviceRepository.findById(deviceId)
    if (!device || device.userId !== userId) {
      throw AuthError.DeviceNotFound()
    }
    await this.deviceRepository.updateDeviceTrustStatus(deviceId, true)
  }

  async untrustDevice(userId: number, deviceId: number): Promise<void> {
    const device = await this.deviceRepository.findById(deviceId)
    if (!device || device.userId !== userId) {
      throw AuthError.DeviceNotFound()
    }
    await this.deviceRepository.updateDeviceTrustStatus(deviceId, false)
    await this.notifyDeviceTrustChange(userId, deviceId, 'untrusted')
  }
}
