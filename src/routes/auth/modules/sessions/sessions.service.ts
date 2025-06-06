import { Injectable, Logger, Inject } from '@nestjs/common'
import { I18nService } from 'nestjs-i18n'
import { AuthError } from 'src/routes/auth/auth.error'
import { ConfigService } from '@nestjs/config'
import { IDeviceService, ISessionService } from 'src/routes/auth/shared/auth.types'
import { EMAIL_SERVICE, GEOLOCATION_SERVICE, DEVICE_SERVICE } from 'src/shared/constants/injection.tokens'
import { PrismaService } from 'src/shared/services/prisma.service'
import { DeviceSessionGroupDto, GetGroupedSessionsResponseDto } from './session.dto'
import { GeolocationService } from 'src/routes/auth/shared/services/common/geolocation.service'
import { SessionRepository, DeviceRepository } from 'src/routes/auth/shared/repositories'
import { Device } from '@prisma/client'
import { I18nPath } from 'src/generated/i18n.generated'

@Injectable()
export class SessionsService implements ISessionService {
  private readonly logger = new Logger(SessionsService.name)

  constructor(
    private readonly i18nService: I18nService,
    private readonly configService: ConfigService,
    private readonly sessionRepository: SessionRepository,
    private readonly deviceRepository: DeviceRepository,
    @Inject(EMAIL_SERVICE) private readonly emailService: GeolocationService,
    private readonly prismaService: PrismaService,
    @Inject(GEOLOCATION_SERVICE) private readonly geolocationService: GeolocationService,
    @Inject(DEVICE_SERVICE) private readonly deviceService: IDeviceService
  ) {}

  /**
   * Lấy danh sách sessions của user, nhóm theo device
   */
  async getSessions(
    userId: number,
    currentPage: number = 1,
    itemsPerPage: number = 5,
    currentSessionIdFromToken: string
  ): Promise<GetGroupedSessionsResponseDto> {
    this.logger.debug(
      `[getSessions] Attempting to get grouped sessions for userId: ${userId}, page: ${currentPage}, limit: ${itemsPerPage}`
    )

    const sessionResult = await this.sessionRepository.findSessionsByUserId(userId, { page: 1, limit: 1000 })
    let devices = await this.deviceRepository.findDevicesByUserId(userId)
    devices = await this.ensureCurrentDeviceIncluded(currentSessionIdFromToken, devices)

    const deviceGroups: DeviceSessionGroupDto[] = []

    for (const device of devices) {
      const currentSessionDetails = await this.sessionRepository.findById(currentSessionIdFromToken)
      const isCurrentDevice = currentSessionDetails?.deviceId === device.id

      const deviceSessions = sessionResult.data.filter((session) => session.deviceId === device.id)

      if (deviceSessions.length === 0) continue

      const deviceInfo = this.parseUserAgentAndApp(deviceSessions[0]?.userAgent ?? '')
      const latestSession = deviceSessions[0]
      const activeSessionsCount = deviceSessions.filter((s) => s.isActive).length
      const lastActive = new Date(latestSession.lastActive)
      const location = await this.getLocationFromIP(latestSession.ipAddress)

      const sessionItems = await Promise.all(
        deviceSessions.map(async (session) => {
          const sessionInfo = this.parseUserAgentAndApp(session.userAgent ?? '')
          const inactiveDuration = session.isActive
            ? null
            : this.calculateInactiveDuration(new Date(session.lastActive))
          const sessionLocation = await this.getLocationFromIP(session.ipAddress)
          const isCurrentSession = session.id === currentSessionIdFromToken

          return {
            id: session.id,
            createdAt: new Date(session.createdAt),
            lastActive: new Date(session.lastActive),
            ipAddress: session.ipAddress,
            location: sessionLocation,
            browser: sessionInfo.browser,
            browserVersion: sessionInfo.browserVersion,
            app: sessionInfo.app,
            isActive: session.isActive,
            inactiveDuration,
            isCurrentSession
          }
        })
      )

      deviceGroups.push({
        deviceId: device.id,
        deviceName: device.name,
        deviceType: deviceInfo.deviceType,
        os: deviceInfo.os,
        osVersion: deviceInfo.osVersion,
        browser: deviceInfo.browser,
        browserVersion: deviceInfo.browserVersion,
        isDeviceTrusted: device.isTrusted,
        deviceTrustExpiration: device.trustExpiration,
        lastActive,
        location,
        activeSessionsCount,
        isCurrentDevice,
        sessions: sessionItems
      })
    }

    deviceGroups.sort((a, b) => (b.lastActive?.getTime() || 0) - (a.lastActive?.getTime() || 0))

    const totalItems = deviceGroups.length
    const totalPages = Math.ceil(totalItems / itemsPerPage)
    const startIndex = (currentPage - 1) * itemsPerPage
    const paginatedDeviceGroups = deviceGroups.slice(startIndex, startIndex + itemsPerPage)

    return {
      devices: paginatedDeviceGroups,
      meta: { currentPage, itemsPerPage, totalItems, totalPages }
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

  private parseUserAgentAndApp(userAgent: string): {
    deviceType: string
    os: string
    osVersion: string
    browser: string
    browserVersion: string
    app: string
  } {
    if (!userAgent) {
      return {
        deviceType: 'Unknown',
        os: 'Unknown',
        osVersion: '',
        browser: 'Unknown',
        browserVersion: '',
        app: 'Unknown'
      }
    }
    // TODO: Replace with a robust user-agent parsing library like 'ua-parser-js'
    return {
      deviceType: 'Desktop',
      os: 'Windows',
      osVersion: '10',
      browser: 'Chrome',
      browserVersion: '108',
      app: 'WebApp'
    }
  }

  private async getLocationFromIP(ip: string): Promise<string> {
    if (!ip) return 'Unknown'
    return this.geolocationService.getLocationFromIP(ip)
  }

  private calculateInactiveDuration(lastActiveDate: Date): string {
    const now = new Date()
    const diffSeconds = Math.floor((now.getTime() - lastActiveDate.getTime()) / 1000)
    if (diffSeconds < 60) return 'Vừa xong'
    const diffMinutes = Math.floor(diffSeconds / 60)
    if (diffMinutes < 60) return `${diffMinutes} phút`
    const diffHours = Math.floor(diffMinutes / 60)
    if (diffHours < 24) return `${diffHours} giờ`
    const diffDays = Math.floor(diffHours / 24)
    if (diffDays < 7) return `${diffDays} ngày`
    return `${Math.floor(diffDays / 7)} tuần`
  }

  async checkIfActionRequiresVerification(
    _userId: number,
    options: { sessionIds?: string[]; deviceIds?: number[] }
  ): Promise<boolean> {
    if (options.deviceIds?.length) return true
    if (options.sessionIds && options.sessionIds.length > 1) return true
    if (options.sessionIds?.length === 1) {
      const session = await this.sessionRepository.findById(options.sessionIds[0])
      if (!session) return false
      const device = await this.deviceRepository.findById(session.deviceId)
      return device?.isTrusted ?? false
    }
    return false
  }

  async revokeItems(
    userId: number,
    options: {
      sessionIds?: string[]
      deviceIds?: number[]
      revokeAllUserSessions?: boolean
      excludeCurrentSession?: boolean
    },
    currentSessionContext: { sessionId?: string; deviceId?: number }
  ): Promise<{ message: string; revokedSessionsCount: number; untrustedDevicesCount: number }> {
    let revokedSessionsCount = 0
    let untrustedDevicesCount = 0
    const excludeSessionId = options.excludeCurrentSession ? currentSessionContext.sessionId : undefined

    if (options.revokeAllUserSessions) {
      const result = await this.invalidateAllUserSessions(userId, undefined, excludeSessionId)
      revokedSessionsCount = result.count
    } else {
      if (options.sessionIds?.length) {
        for (const sessionId of options.sessionIds) {
          if (sessionId === excludeSessionId) continue
          await this.revokeSingleSession(sessionId, userId)
          revokedSessionsCount++
        }
      }
      if (options.deviceIds?.length) {
        for (const deviceId of options.deviceIds) {
          if (deviceId === currentSessionContext.deviceId && options.excludeCurrentSession) continue
          const result = await this.revokeDevice(deviceId, userId, excludeSessionId)
          revokedSessionsCount += result.revokedSessionsCount
          if (result.untrusted) untrustedDevicesCount++
        }
      }
    }

    const message: string =
      revokedSessionsCount > 0
        ? this.i18nService.t('auth.Auth.Session.RevokedSuccessfullyCount' as I18nPath, {
            args: { count: revokedSessionsCount }
          })
        : this.i18nService.t('auth.Auth.Session.NoSessionsToRevoke' as I18nPath)

    return { message, revokedSessionsCount, untrustedDevicesCount }
  }

  private async revokeSingleSession(sessionId: string, userId: number): Promise<void> {
    const session = await this.sessionRepository.findById(sessionId)
    if (session?.userId !== userId) throw AuthError.InsufficientPermissions()
    await this.sessionRepository.deleteSession(sessionId)
  }

  private async revokeDevice(
    deviceId: number,
    userId: number,
    excludeSessionId?: string
  ): Promise<{ revokedSessionsCount: number; untrusted: boolean }> {
    const device = await this.deviceRepository.findById(deviceId)
    if (device?.userId !== userId) throw AuthError.DeviceNotOwnedByUser()

    const { data: sessions } = await this.sessionRepository.findSessionsByUserId(userId, { page: 1, limit: 1000 })
    const sessionsOnDevice = sessions.filter((s) => s.deviceId === deviceId)

    let revokedCount = 0
    for (const session of sessionsOnDevice) {
      if (session.id === excludeSessionId) continue
      await this.sessionRepository.deleteSession(session.id)
      revokedCount++
    }

    let wasUntrusted = false
    if (device.isTrusted) {
      await this.deviceRepository.updateDeviceTrustStatus(deviceId, false)
      wasUntrusted = true
    }

    return { revokedSessionsCount: revokedCount, untrusted: wasUntrusted }
  }

  async updateDeviceName(userId: number, deviceId: number, name: string): Promise<void> {
    const device = await this.deviceRepository.findById(deviceId)
    if (device?.userId !== userId) throw AuthError.DeviceNotOwnedByUser()
    await this.deviceRepository.updateDeviceName(deviceId, name)
  }

  async trustCurrentDevice(userId: number, deviceId: number): Promise<void> {
    const device = await this.deviceRepository.findById(deviceId)
    if (device?.userId !== userId) throw AuthError.DeviceNotOwnedByUser()
    if (device.isTrusted && device.trustExpiration && new Date() < device.trustExpiration) return
    await this.deviceRepository.updateDeviceTrustStatus(deviceId, true)
  }

  async untrustDevice(userId: number, deviceId: number): Promise<void> {
    const device = await this.deviceRepository.findById(deviceId)
    if (device?.userId !== userId) throw AuthError.DeviceNotOwnedByUser()
    if (!device.isTrusted) return
    await this.deviceRepository.updateDeviceTrustStatus(deviceId, false)
  }

  async isSessionInvalidated(sessionId: string): Promise<boolean> {
    const session = await this.sessionRepository.findById(sessionId)
    return !session
  }

  async invalidateSession(sessionId: string): Promise<void> {
    this.logger.debug(`[invalidateSession] Deleting session ${sessionId} via repository.`)
    await this.sessionRepository.deleteSession(sessionId)
  }

  async invalidateAllUserSessions(
    userId: number,
    _reason?: string,
    sessionIdToExclude?: string
  ): Promise<{ count: number }> {
    this.logger.warn(`Invalidating all sessions for user ${userId}, excluding ${sessionIdToExclude}`)
    return this.sessionRepository.deleteAllUserSessions(userId, sessionIdToExclude)
  }
}
