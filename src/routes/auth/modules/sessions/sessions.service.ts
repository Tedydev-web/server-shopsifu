import { Injectable, Logger, Inject, forwardRef } from '@nestjs/common'
import { I18nService } from 'nestjs-i18n'
import { AuthError } from 'src/routes/auth/auth.error'
import { ConfigService } from '@nestjs/config'
import { IDeviceService, ISessionService, ITokenService } from 'src/routes/auth/shared/auth.types'
import * as crypto from 'crypto'
import {
  EMAIL_SERVICE,
  REDIS_SERVICE,
  TOKEN_SERVICE,
  DEVICE_SERVICE,
  GEOLOCATION_SERVICE
} from 'src/shared/constants/injection.tokens'
import { EmailService, SecurityAlertType } from 'src/routes/auth/shared/services/common/email.service'
import { PrismaService } from 'src/shared/services/prisma.service'
import { DeviceSessionGroupDto, GetGroupedSessionsResponseDto } from './session.dto'
import { GeolocationService } from 'src/routes/auth/shared/services/common/geolocation.service'
import { RedisService } from 'src/providers/redis/redis.service'
import { SessionRepository, Session, DeviceRepository } from 'src/routes/auth/shared/repositories'
import { RedisKeyManager } from 'src/shared/utils/redis-keys.utils'
import { DEVICE_REVOKE_HISTORY_TTL } from 'src/shared/constants/auth.constants'
import { Device } from '@prisma/client'
import { DeviceService } from 'src/routes/auth/shared/services/device.service'

@Injectable()
export class SessionsService implements ISessionService {
  private readonly logger = new Logger(SessionsService.name)

  constructor(
    @Inject(TOKEN_SERVICE) private readonly tokenService: ITokenService,
    private readonly i18nService: I18nService,
    private readonly configService: ConfigService,
    private readonly sessionRepository: SessionRepository,
    private readonly deviceRepository: DeviceRepository,
    @Inject(EMAIL_SERVICE) private readonly emailService: EmailService,
    private readonly prismaService: PrismaService,
    @Inject(GEOLOCATION_SERVICE) private readonly geolocationService: GeolocationService,
    @Inject(REDIS_SERVICE) private readonly redisService: RedisService,
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
      `[getSessions] Attempting to get grouped sessions for userId: ${userId}, page: ${currentPage}, limit: ${itemsPerPage}, currentSessionId: ${currentSessionIdFromToken}`
    )

    const sessionResult = await this.sessionRepository.findSessionsByUserId(userId, { page: 1, limit: 1000 })
    let devices = await this.deviceRepository.findDevicesByUserId(userId)
    devices = await this.ensureCurrentDevice(userId, currentSessionIdFromToken, devices, sessionResult.data)

    const deviceGroups: DeviceSessionGroupDto[] = []

    for (const device of devices) {
      const isCurrentDevice = device.id === (await this.sessionRepository.findById(currentSessionIdFromToken))?.deviceId
      const deviceSessions = sessionResult.data.filter((session) => session.deviceId === device.id)

      if (isCurrentDevice && deviceSessions.length === 0) {
        const currentSession = await this.sessionRepository.findById(currentSessionIdFromToken)
        if (currentSession) deviceSessions.push(currentSession)
      }

      if (deviceSessions.length === 0) continue

      const deviceInfo = this.parseUserAgentAndApp(deviceSessions[0]?.userAgent || device.userAgent || 'Unknown')
      deviceSessions.sort((a, b) => b.lastActive.getTime() - a.lastActive.getTime())
      const latestSession = deviceSessions[0]
      const activeSessionsCount = deviceSessions.filter((s) => s.isActive).length
      const lastActive = latestSession?.lastActive || device.lastActive
      const location = await this.getLocationFromIP(latestSession?.ipAddress || device.ip)

      const sessionItems = await Promise.all(
        deviceSessions.map(async (session) => {
          const sessionInfo = this.parseUserAgentAndApp(session.userAgent)
          const inactiveDuration = session.isActive ? null : this.calculateInactiveDuration(session.lastActive)
          const sessionLocation = await this.getLocationFromIP(session.ipAddress)
          const isCurrentSession = session.id === currentSessionIdFromToken

          return {
            id: session.id,
            createdAt: session.createdAt,
            lastActive: session.lastActive,
            ipAddress: session.ipAddress,
            location: sessionLocation,
            browser: sessionInfo.browser,
            browserVersion: sessionInfo.browserVersion,
            app: sessionInfo.app,
            isActive: session.isActive !== undefined ? session.isActive : true,
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

    this.logger.debug(
      `[getSessions] Pagination: totalItems=${totalItems}, totalPages=${totalPages}, returning ${paginatedDeviceGroups.length} device groups for page ${currentPage}`
    )

    return {
      devices: paginatedDeviceGroups,
      meta: { currentPage, itemsPerPage, totalItems, totalPages }
    }
  }

  /**
   * Đảm bảo thiết bị hiện tại được thêm vào danh sách nếu cần
   */
  private async ensureCurrentDevice(
    userId: number,
    currentSessionId: string,
    devices: Device[],
    sessions: Session[]
  ): Promise<Device[]> {
    const currentSession = await this.sessionRepository.findById(currentSessionId)
    if (!currentSession || !currentSession.deviceId) return devices

    const currentDeviceId = currentSession.deviceId
    const hasCurrentDevice = devices.some((device) => device.id === currentDeviceId)

    if (!hasCurrentDevice) {
      this.logger.debug(`[getSessions] Current device ${currentDeviceId} not in results, adding it manually`)
      const currentDevice = await this.deviceRepository.findById(currentDeviceId)
      if (currentDevice) {
        devices.push(currentDevice)
        this.logger.debug(`[getSessions] Added current device ${currentDeviceId} from database`)
      }
    }

    if (!sessions.some((session) => session.id === currentSessionId)) {
      sessions.push(currentSession)
    }

    return devices
  }

  /**
   * Phân tích chuỗi User-Agent để lấy thông tin thiết bị, hệ điều hành, trình duyệt và ứng dụng
   */
  private parseUserAgentAndApp(userAgent: string): {
    deviceType: string
    os: string
    osVersion: string
    browser: string
    browserVersion: string
    app: string
  } {
    try {
      const userAgentLower = userAgent.toLowerCase()
      let deviceType = 'Desktop'
      let os = 'Unknown'
      let osVersion = ''
      let browser = 'Unknown'
      let browserVersion = ''
      let app = 'Unknown App'

      if (
        userAgentLower.includes('mobile') ||
        userAgentLower.includes('android') ||
        userAgentLower.includes('iphone')
      ) {
        deviceType = 'Mobile'
      } else if (userAgentLower.includes('tablet') || userAgentLower.includes('ipad')) {
        deviceType = 'Tablet'
      }

      if (userAgentLower.includes('windows')) {
        os = 'Windows'
        const windowsMatch = userAgentLower.match(/windows nt (\d+\.\d+)/)
        if (windowsMatch) {
          const ntVersion = parseFloat(windowsMatch[1])
          osVersion =
            ntVersion === 10.0
              ? '10'
              : ntVersion === 6.3
                ? '8.1'
                : ntVersion === 6.2
                  ? '8'
                  : ntVersion === 6.1
                    ? '7'
                    : ntVersion.toString()
        }
      } else if (userAgentLower.includes('macintosh') || userAgentLower.includes('mac os')) {
        os = 'macOS'
        const macMatch = userAgentLower.match(/mac os x (\d+[._]\d+[._]?\d*)/)
        if (macMatch) osVersion = macMatch[1].replace(/_/g, '.')
      } else if (userAgentLower.includes('linux')) {
        os = 'Linux'
      } else if (userAgentLower.includes('android')) {
        os = 'Android'
        const androidMatch = userAgentLower.match(/android (\d+(\.\d+)*)/)
        if (androidMatch) osVersion = androidMatch[1]
      } else if (
        userAgentLower.includes('iphone') ||
        userAgentLower.includes('ipad') ||
        userAgentLower.includes('ipod')
      ) {
        os = 'iOS'
        const iosMatch = userAgentLower.match(/os (\d+[._]\d+[._]?\d*)/)
        if (iosMatch) osVersion = iosMatch[1].replace(/_/g, '.')
      }

      if (userAgentLower.includes('edge') || userAgentLower.includes('edg/')) {
        browser = 'Edge'
        app = 'Microsoft Edge'
        const edgeMatch = userAgentLower.match(/edge?\/(\d+(\.\d+)*)/)
        if (edgeMatch) browserVersion = edgeMatch[1]
      } else if (userAgentLower.includes('chrome')) {
        browser = 'Chrome'
        app = 'Google Chrome'
        const chromeMatch = userAgentLower.match(/chrome\/(\d+(\.\d+)*)/)
        if (chromeMatch) browserVersion = chromeMatch[1]
      } else if (userAgentLower.includes('firefox')) {
        browser = 'Firefox'
        app = 'Firefox'
        const firefoxMatch = userAgentLower.match(/firefox\/(\d+(\.\d+)*)/)
        if (firefoxMatch) browserVersion = firefoxMatch[1]
      } else if (userAgentLower.includes('safari') && !userAgentLower.includes('chrome')) {
        browser = 'Safari'
        app = 'Safari'
        const safariMatch = userAgentLower.match(/version\/(\d+(\.\d+)*)/)
        if (safariMatch) browserVersion = safariMatch[1]
      } else if (userAgentLower.includes('opera') || userAgentLower.includes('opr/')) {
        browser = 'Opera'
        app = 'Opera'
        const operaMatch = userAgentLower.match(/(?:opera|opr)\/(\d+(\.\d+)*)/)
        if (operaMatch) browserVersion = operaMatch[1]
      } else if (userAgentLower.includes('instagram')) {
        app = 'Instagram'
      } else if (userAgentLower.includes('youtube')) {
        app = 'YouTube'
      } else if (userAgentLower.includes('facebook')) {
        app = 'Facebook'
      } else if (userAgentLower.includes('twitter')) {
        app = 'Twitter'
      } else if (userAgentLower.includes('linkedin')) {
        app = 'LinkedIn'
      }

      return { deviceType, os, osVersion, browser, browserVersion, app }
    } catch (error) {
      this.logger.error(`[parseUserAgentAndApp] Error parsing user agent: ${error.message}`)
      return {
        deviceType: 'Unknown',
        os: 'Unknown',
        osVersion: '',
        browser: 'Unknown',
        browserVersion: '',
        app: 'Unknown App'
      }
    }
  }

  /**
   * Lấy thông tin vị trí từ địa chỉ IP
   */
  private async getLocationFromIP(ip: string): Promise<string> {
    try {
      return await this.geolocationService.getLocationFromIP(ip)
    } catch (error) {
      this.logger.error(`Lỗi khi lấy thông tin vị trí từ IP ${ip}: ${error.message}`)
      return 'Việt Nam'
    }
  }

  /**
   * Tính toán thời gian không hoạt động
   */
  private calculateInactiveDuration(lastActiveDate: Date): string {
    const now = new Date()
    const lastActive = new Date(lastActiveDate)
    if (lastActive > now) return 'Vừa xong'

    const diffMs = now.getTime() - lastActive.getTime()
    const diffSeconds = Math.floor(diffMs / 1000)

    if (diffSeconds < 60) return 'Vừa xong'
    const diffMinutes = Math.floor(diffSeconds / 60)
    if (diffMinutes < 60) return `${diffMinutes} phút`
    const diffHours = Math.floor(diffMinutes / 60)
    if (diffHours < 24) return `${diffHours} giờ`
    const diffDays = Math.floor(diffHours / 24)
    if (diffDays < 7) return `${diffDays} ngày`
    const diffWeeks = Math.floor(diffDays / 7)
    if (diffWeeks < 4) return `${diffWeeks} tuần`
    const diffMonths = Math.floor(diffDays / 30)
    if (diffMonths < 12) return `${diffMonths} tháng`
    const diffYears = Math.floor(diffDays / 365)
    return `${diffYears} năm`
  }

  /**
   * Thu hồi nhiều sessions hoặc devices
   */
  async revokeItems(
    userId: number,
    options: {
      sessionIds?: string[]
      deviceIds?: number[]
      revokeAllUserSessions?: boolean
      excludeCurrentSession?: boolean
    },
    currentSessionDetails?: { sessionId?: string; deviceId?: number },
    verificationToken?: string,
    otpCode?: string,
    ipAddress?: string,
    userAgent?: string
  ): Promise<{
    message: string
    revokedSessionsCount: number
    revokedDevicesCount: number
    untrustedDevicesCount: number
    revokedSessionIds?: string[]
    revokedDeviceIds?: number[]
    requiresAdditionalVerification?: boolean
    verificationRedirectUrl?: string
  }> {
    const currentSessionId = currentSessionDetails?.sessionId
    const currentDeviceId = currentSessionDetails?.deviceId
    let revokedSessionsCount = 0
    let revokedDevicesCount = 0
    let untrustedDevicesCount = 0
    const revokedSessionIds: string[] = []
    const revokedDeviceIds: number[] = []

    const requiresTwoFactorAuth = await this.checkIfActionRequiresVerification(userId, options)
    const user = await this.getUserInfo(userId, { twoFactorEnabled: true, email: true })

    if (requiresTwoFactorAuth && user?.twoFactorEnabled && !otpCode && !verificationToken) {
      const action = options.revokeAllUserSessions ? 'revoke-all-sessions' : 'revoke-sessions'
      return {
        message: this.i18nService.t('auth.Auth.Session.RequiresAdditionalVerification'),
        revokedSessionsCount: 0,
        revokedDevicesCount: 0,
        untrustedDevicesCount: 0,
        requiresAdditionalVerification: true,
        verificationRedirectUrl: `/auth/verify-action?action=${action}`
      }
    }

    if (options.sessionIds?.length) {
      for (const sessionId of options.sessionIds) {
        if (options.excludeCurrentSession && sessionId === currentSessionId) continue
        const session = await this.sessionRepository.findById(sessionId)
        await this.verifyOwnership(session, userId, 'session')
        await this.revokeSingleSession(sessionId, userId, 'BULK_REVOKE_BY_USER')
        revokedSessionsCount++
        revokedSessionIds.push(sessionId)
      }
    }

    if (options.deviceIds?.length) {
      for (const deviceId of options.deviceIds) {
        if (options.excludeCurrentSession && deviceId === currentDeviceId) continue
        const { revokedSessionsCount: sessionCount, untrusted } = await this.revokeSingleDevice(
          deviceId,
          userId,
          currentSessionId
        )
        revokedSessionsCount += sessionCount
        revokedDevicesCount++
        revokedDeviceIds.push(deviceId)
        if (untrusted) untrustedDevicesCount++
      }
    }

    if (options.revokeAllUserSessions) {
      const allDevices = await this.deviceRepository.findDevicesByUserId(userId)
      for (const device of allDevices) {
        if (options.excludeCurrentSession && device.id === currentDeviceId) continue
        const { revokedSessionsCount: sessionCount, untrusted } = await this.revokeSingleDevice(
          device.id,
          userId,
          currentSessionId
        )
        revokedSessionsCount += sessionCount
        revokedDevicesCount++
        revokedDeviceIds.push(device.id)
        if (untrusted) untrustedDevicesCount++
      }
    }

    if (revokedDevicesCount > 0 || revokedSessionsCount >= 3) {
      await this.sendSecurityAlert(userId, SecurityAlertType.SESSIONS_REVOKED, {
        sessionCount: revokedSessionsCount,
        deviceCount: revokedDevicesCount,
        ipAddress,
        userAgent
      })
    }

    return {
      message:
        revokedSessionsCount === 0
          ? this.i18nService.t('auth.Auth.Session.NoSessionsToRevoke')
          : this.i18nService.t('auth.Auth.Session.RevokedSuccessfullyCount', { args: { count: revokedSessionsCount } }),
      revokedSessionsCount,
      revokedDevicesCount,
      untrustedDevicesCount,
      revokedSessionIds,
      revokedDeviceIds
    }
  }

  /**
   * Thu hồi một session
   */
  private async revokeSingleSession(sessionId: string, userId: number, reason: string): Promise<void> {
    const session = await this.sessionRepository.findById(sessionId)
    if (session && session.userId === userId) {
      await this.sessionRepository.archiveSession(sessionId)
      await this.invalidateSession(sessionId, reason)
      if (session.deviceId) {
        await this.deviceService.markDeviceForReverification(userId, session.deviceId, reason)
      }
    }
  }

  /**
   * Thu hồi một device
   */
  private async revokeSingleDevice(
    deviceId: number,
    userId: number,
    excludeSessionId?: string
  ): Promise<{ revokedSessionsCount: number; untrusted: boolean }> {
    const device = await this.deviceRepository.findById(deviceId)
    await this.verifyOwnership(device, userId, 'device')

    const sessions = await this.getDeviceSessions(userId, deviceId)
    let revokedSessionsCount = 0
    let untrusted = false

    for (const session of sessions) {
      if (excludeSessionId && session.id === excludeSessionId) continue
      await this.revokeSingleSession(session.id, userId, 'DEVICE_REVOKE_BY_USER')
      revokedSessionsCount++
    }

    await this.deviceRepository.markDeviceAsInactive(deviceId)
    if (device?.isTrusted) {
      await this.deviceRepository.updateDeviceTrustStatus(deviceId, false)
      untrusted = true
    }

    return { revokedSessionsCount, untrusted }
  }

  /**
   * Lấy tất cả sessions của một device
   */
  private async getDeviceSessions(userId: number, deviceId: number): Promise<Session[]> {
    const allSessions = await this.sessionRepository.findSessionsByUserId(userId, { page: 1, limit: 1000 })
    return allSessions.data.filter((session) => session.deviceId === deviceId)
  }

  /**
   * Cập nhật tên thiết bị
   */
  async updateDeviceName(userId: number, deviceId: number, name: string): Promise<{ message: string }> {
    const device = await this.deviceRepository.findById(deviceId)
    await this.verifyOwnership(device, userId, 'device')
    await this.deviceRepository.updateDeviceName(deviceId, name)
    return { message: this.i18nService.t('auth.Auth.Device.NameUpdatedSuccessfully') }
  }

  /**
   * Tạo device fingerprint
   */
  private generateFingerprint(userAgent: string, ip: string): string {
    const data = `${userAgent}|${ip}`
    return crypto.createHash('md5').update(data).digest('hex')
  }

  /**
   * Đánh dấu thiết bị là đáng tin cậy
   */
  async trustDevice(userId: number, deviceId: number, ip?: string, userAgent?: string): Promise<{ message: string }> {
    const device = await this.deviceRepository.findById(deviceId)
    await this.verifyOwnership(device, userId, 'device')

    if (device?.isTrusted && device.trustExpiration && new Date() < device.trustExpiration) {
      return { message: this.i18nService.t('auth.Auth.Device.AlreadyTrusted') }
    }

    if (userAgent && ip) {
      const fingerprint = this.generateFingerprint(userAgent, ip)
      await this.deviceRepository.updateDeviceFingerprint(deviceId, fingerprint)
    }

    await this.deviceRepository.updateDeviceTrustStatus(deviceId, true)

    await this.sendSecurityAlert(userId, SecurityAlertType.DEVICE_TRUSTED, {
      ipAddress: ip || device?.ip,
      userAgent: userAgent || device?.userAgent,
      deviceName: device?.name || undefined,
      location: device?.lastKnownCity ? `${device?.lastKnownCity}, ${device?.lastKnownCountry}` : undefined
    })

    return { message: this.i18nService.t('auth.Auth.Device.Trusted') }
  }

  /**
   * Bỏ đánh dấu thiết bị là đáng tin cậy
   */
  async untrustDevice(userId: number, deviceId: number): Promise<{ message: string }> {
    const device = await this.deviceRepository.findById(deviceId)
    await this.verifyOwnership(device, userId, 'device')

    if (!device?.isTrusted) {
      return { message: this.i18nService.t('auth.Auth.Device.AlreadyUntrusted') }
    }

    await this.deviceRepository.updateDeviceTrustStatus(deviceId, false)
    await this.sendSecurityAlert(userId, SecurityAlertType.DEVICE_UNTRUSTED, { deviceName: device?.name || undefined })
    return { message: this.i18nService.t('auth.Auth.Device.Untrusted') }
  }

  /**
   * Đánh dấu thiết bị hiện tại là đáng tin cậy
   */
  async trustCurrentDevice(
    userId: number,
    currentDeviceId: number,
    ip?: string,
    userAgent?: string
  ): Promise<{ message: string }> {
    return this.trustDevice(userId, currentDeviceId, ip, userAgent)
  }

  /**
   * Kiểm tra xem hành động có yêu cầu xác thực bổ sung không
   */
  async checkIfActionRequiresVerification(
    userId: number,
    options: {
      sessionIds?: string[]
      deviceIds?: number[]
      revokeAllUserSessions?: boolean
      excludeCurrentSession?: boolean
    }
  ): Promise<boolean> {
    const user = await this.getUserInfo(userId, { twoFactorEnabled: true })
    if (user.twoFactorEnabled) return true
    if (options.revokeAllUserSessions) return true
    if (options.deviceIds && options.deviceIds.length > 0) return true
    if (options.sessionIds && options.sessionIds.length > 1) return true
    return false
  }

  /**
   * Lấy thông tin người dùng
   */
  private async getUserInfo(
    userId: number,
    select: { email?: boolean; twoFactorEnabled?: boolean; userProfile?: boolean } = {}
  ) {
    const user = await this.prismaService.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        email: select.email ?? true,
        twoFactorEnabled: select.twoFactorEnabled ?? false,
        userProfile: select.userProfile ?? false
      }
    })
    if (!user) throw new Error(`User with ID ${userId} not found`)
    return user
  }

  /**
   * Gửi email thông báo bảo mật
   */
  private async sendSecurityAlert(
    userId: number,
    alertType: SecurityAlertType,
    extraData: {
      sessionCount?: number
      deviceCount?: number
      ipAddress?: string
      userAgent?: string
      deviceName?: string
      location?: string
    }
  ): Promise<void> {
    const user = await this.getUserInfo(userId, { email: true, userProfile: true })
    if (!user.email) return

    const location =
      extraData.location ||
      (extraData.ipAddress ? await this.geolocationService.getLocationFromIP(extraData.ipAddress) : 'Unknown')

    await this.emailService.sendSecurityAlertEmail(alertType, user.email, {
      userName: user.userProfile?.firstName || user.email,
      ipAddress: extraData.ipAddress || 'Không xác định',
      device: extraData.userAgent || 'Không xác định',
      location,
      deviceName: extraData.deviceName || 'Unknown device',
      sessionCount: extraData.sessionCount,
      deviceCount: extraData.deviceCount
    })
  }

  /**
   * Kiểm tra quyền sở hữu
   */
  private async verifyOwnership<T extends { userId: number }>(
    entity: T | null,
    userId: number,
    entityType: string
  ): Promise<void> {
    if (!entity || entity.userId !== userId) {
      throw AuthError.DeviceNotOwnedByUser()
    }
    return Promise.resolve()
  }

  /**
   * Vô hiệu hóa một session cụ thể.
   * @param sessionId ID của session cần vô hiệu hóa
   * @param reason Lý do vô hiệu hóa
   */
  async invalidateSession(sessionId: string, reason: string = 'UNKNOWN'): Promise<void> {
    try {
      const isAlreadyInvalidated = await this.isSessionInvalidated(sessionId)
      if (isAlreadyInvalidated) {
        this.logger.debug(`[invalidateSession] Session ${sessionId} is already invalidated. Skipping.`)
        return
      }

      const sessionKey = RedisKeyManager.sessionKey(sessionId)
      const sessionData = await this.redisService.hgetall(sessionKey)

      if (!sessionData || Object.keys(sessionData).length === 0) {
        this.logger.warn(
          `[invalidateSession] No data found for session ${sessionId} in Redis. Cannot process full invalidation logic. Marking as invalidated.`
        )
        // Dù không có data, vẫn đánh dấu là invalidated để isSessionInvalidated() trả về true
        const invalidatedKeyFallback = RedisKeyManager.sessionInvalidatedKey(sessionId)
        await this.redisService.set(
          invalidatedKeyFallback,
          reason,
          'EX',
          this.configService.get<number>('auth.session.invalidatedTtl', 7 * 24 * 60 * 60)
        )
        return
      }

      const userId = parseInt(sessionData.userId, 10)
      const deviceId = parseInt(sessionData.deviceId, 10)

      // Lưu lại thông tin session bị vô hiệu hoá
      await this.archiveRevokedSession(sessionId, sessionData, reason)

      // Đánh dấu session là đã vô hiệu hoá
      const invalidatedKey = RedisKeyManager.sessionInvalidatedKey(sessionId)
      await this.redisService.set(
        invalidatedKey,
        reason,
        'EX',
        this.configService.get<number>('auth.session.invalidatedTtl', 7 * 24 * 60 * 60)
      )

      // Xoá session data khỏi Redis
      await this.redisService.del(sessionKey)
      this.logger.log(`Session ${sessionId} data deleted from Redis. Reason: ${reason}`)

      // Xoá session khỏi các index
      if (userId) {
        await this.redisService.srem(RedisKeyManager.userSessionsKey(userId), sessionId)
        this.logger.debug(`Session ${sessionId} removed from user index for user ${userId}.`)
      }
      if (deviceId) {
        await this.redisService.srem(RedisKeyManager.deviceSessionsKey(deviceId), sessionId)
        this.logger.debug(`Session ${sessionId} removed from device index for device ${deviceId}.`)
      }

      if (deviceId && userId && this.deviceRepository) {
        const deviceSessionsKey = RedisKeyManager.deviceSessionsKey(deviceId)
        const activeSessionIdsOnDevice = await this.redisService.smembers(deviceSessionsKey)

        let hasOtherActiveSessionsOnDevice = false
        if (activeSessionIdsOnDevice && activeSessionIdsOnDevice.length > 0) {
          for (const activeSessionId of activeSessionIdsOnDevice) {
            if (activeSessionId === sessionId) continue // Bỏ qua session vừa bị revoke
            const activeSessionData = await this.redisService.hgetall(RedisKeyManager.sessionKey(activeSessionId))
            if (activeSessionData && activeSessionData.isActive === '1') {
              hasOtherActiveSessionsOnDevice = true
              break
            }
          }
        }

        if (!hasOtherActiveSessionsOnDevice) {
          this.logger.log(`Session ${sessionId} was the last active session on device ${deviceId}. Untrusting device.`)
          await this.deviceRepository.updateDeviceTrustStatus(deviceId, false)
        } else {
          // Nếu không phải session cuối cùng, đặt cờ yêu cầu xác minh lại cho thiết bị
          const reverifyKey = RedisKeyManager.customKey('device:needs_reverify_after_revoke', deviceId.toString())
          await this.redisService.set(reverifyKey, 'true', 'EX', 300) // 5 phút TTL
          this.logger.debug(
            `Device ${deviceId} marked for reverification after session ${sessionId} revoke. Key: ${reverifyKey}`
          )
        }
      } else {
        this.logger.warn(
          `[invalidateSession] DeviceRepository not available. Skipping device untrust/re-verify logic for session ${sessionId}.`
        )
      }

      this.logger.log(`Session ${sessionId} has been invalidated successfully. Reason: ${reason}`)
    } catch (error) {
      this.logger.error(`Error invalidating session ${sessionId}: ${error.message}`, error.stack)
    }
  }

  /**
   * Lưu trữ thông tin session đã bị thu hồi vào một key riêng để audit hoặc xử lý sau.
   */
  private async archiveRevokedSession(
    sessionId: string,
    sessionData: Record<string, any>,
    reason: string
  ): Promise<void> {
    try {
      const archivedKey = RedisKeyManager.sessionArchivedKey(sessionId)
      const historyKey = RedisKeyManager.sessionRevokeHistoryKey(sessionId)

      // Lưu nội dung session đã vô hiệu hoá
      if (this.geolocationService['cryptoService']) {
        // Sử dụng cryptoService từ geolocationService
        const cryptoService = this.geolocationService['cryptoService']
        // Mã hoá dữ liệu nhạy cảm trước khi lưu
        const encryptedData = cryptoService.encrypt({
          ...sessionData,
          revokedAt: Date.now(),
          reason
        })
        await this.redisService.set(
          archivedKey,
          encryptedData,
          'EX',
          this.configService.get('auth.session.archiveTtl', 30 * 24 * 60 * 60)
        )
      } else {
        await this.redisService.hset(archivedKey, {
          ...sessionData,
          revokedAt: Date.now(),
          reason
        })
        await this.redisService.expire(
          archivedKey,
          this.configService.get('auth.session.archiveTtl', 30 * 24 * 60 * 60)
        )
      }

      // Lưu lịch sử vô hiệu hoá
      await this.redisService.lpush(
        historyKey,
        JSON.stringify({
          timestamp: Date.now(),
          reason
        })
      )

      // Giới hạn kích thước của lịch sử
      await this.redisService.ltrim(historyKey, 0, 9) // Giữ 10 mục mới nhất
      await this.redisService.expire(historyKey, DEVICE_REVOKE_HISTORY_TTL)
    } catch (error) {
      this.logger.error(`Error archiving session ${sessionId}: ${error.message}`, error.stack)
    }
  }

  /**
   * Kiểm tra xem một session có bị đánh dấu là đã vô hiệu hóa không.
   */
  async isSessionInvalidated(sessionId: string): Promise<boolean> {
    try {
      if (!sessionId) {
        return true
      }

      // Kiểm tra key trong Redis
      const invalidatedKey = RedisKeyManager.sessionInvalidatedKey(sessionId)
      const exists = await this.redisService.exists(invalidatedKey)

      // Kiểm tra key session
      if (exists === 0) {
        const sessionKey = RedisKeyManager.sessionKey(sessionId)
        const sessionExists = await this.redisService.exists(sessionKey)
        if (sessionExists === 0) {
          // Session không tồn tại trong Redis, coi như đã bị vô hiệu hoá
          return true
        }
      }

      return exists > 0
    } catch (error) {
      this.logger.error(`Error checking if session ${sessionId} is invalidated: ${error.message}`, error.stack)
      // Trong trường hợp lỗi, coi như session đã bị vô hiệu hoá để an toàn
      return true
    }
  }

  /**
   * Vô hiệu hóa tất cả các session của một người dùng.
   */
  async invalidateAllUserSessions(
    userId: number,
    reason: string = 'UNKNOWN_BULK_INVALIDATION',
    sessionIdToExclude?: string
  ): Promise<void> {
    try {
      interface RedisOperation {
        command: string
        args: any[]
      }

      // Get all sessions for this user
      const sessionPattern = `session:*:${userId}:*`
      const sessions = await this.redisService.keys(sessionPattern)

      if (sessions.length === 0) {
        return
      }

      const operations: RedisOperation[] = []

      for (const sessionKey of sessions) {
        // Extract session ID from key
        const sessionId = sessionKey.split(':')[1]

        if (sessionIdToExclude && sessionId === sessionIdToExclude) {
          continue
        }

        // Check if session data exists
        const sessionData = await this.redisService.hgetall(sessionKey)

        if (Object.keys(sessionData).length > 0) {
          // Archive the session
          const archivedKey = RedisKeyManager.sessionArchivedKey(sessionId)

          if (this.geolocationService['cryptoService']) {
            const cryptoService = this.geolocationService['cryptoService']
            operations.push({
              command: 'set',
              args: [
                archivedKey,
                cryptoService.encrypt({
                  ...sessionData,
                  revokedAt: Date.now(),
                  reason
                }),
                'EX',
                this.configService.get('auth.session.archiveTtl', 30 * 24 * 60 * 60)
              ]
            })
          } else {
            const archiveDataEntries = Object.entries({
              ...sessionData,
              revokedAt: Date.now().toString(),
              reason
            }).flat()

            operations.push({
              command: 'hset',
              args: [archivedKey, ...archiveDataEntries]
            })

            operations.push({
              command: 'expire',
              args: [archivedKey, this.configService.get('auth.session.archiveTtl', 30 * 24 * 60 * 60)]
            })
          }

          // Mark session as invalidated
          const invalidatedKey = RedisKeyManager.sessionInvalidatedKey(sessionId)
          operations.push({
            command: 'set',
            args: [
              invalidatedKey,
              reason,
              'EX',
              this.configService.get('auth.session.invalidatedTtl', 7 * 24 * 60 * 60)
            ]
          })

          // Delete session
          operations.push({
            command: 'del',
            args: [sessionKey]
          })

          // Add to history
          const historyKey = RedisKeyManager.sessionRevokeHistoryKey(sessionId)
          operations.push({
            command: 'lpush',
            args: [
              historyKey,
              JSON.stringify({
                timestamp: Date.now(),
                reason
              })
            ]
          })

          operations.push({
            command: 'ltrim',
            args: [historyKey, 0, 9]
          })

          operations.push({
            command: 'expire',
            args: [historyKey, DEVICE_REVOKE_HISTORY_TTL]
          })
        }
      }

      // Execute all operations
      if (operations.length > 0) {
        await this.redisService.batchProcess(operations)
      }

      this.logger.log(`All sessions for user ${userId} have been invalidated. Reason: ${reason}`)
    } catch (error) {
      this.logger.error(`Error invalidating all sessions for user ${userId}: ${error.message}`, error.stack)
      throw error
    }
  }

  /**
   * Lấy thông tin người dùng theo ID
   */
  async getUserById(userId: number) {
    return this.getUserInfo(userId, { email: true, twoFactorEnabled: true })
  }
}
