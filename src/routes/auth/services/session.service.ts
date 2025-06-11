// ================================================================
// NestJS Dependencies
// ================================================================
import { Injectable, Logger, Inject } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { I18nService } from 'nestjs-i18n'

// ================================================================
// External Libraries
// ================================================================
import { Response } from 'express'
import { z } from 'zod'

// ================================================================
// Internal Services & Types
// ================================================================
import { PrismaService } from 'src/shared/providers/prisma/prisma.service'
import { RedisService } from 'src/shared/providers/redis/redis.service'
import { RedisKeyManager } from 'src/shared/providers/redis/redis-keys.utils'
import { GeolocationService, GeoLocationResult } from 'src/shared/services/geolocation.service'
import { EmailService } from 'src/shared/services/email.service'
import { UserAgentService } from '../../../shared/services/user-agent.service'

// ================================================================
// Repositories
// ================================================================
import { SessionRepository } from 'src/routes/auth/repositories'
import { DeviceRepository } from 'src/shared/repositories/device.repository'

// ================================================================
// Constants & Injection Tokens
// ================================================================
import {
  DEVICE_SERVICE,
  EMAIL_SERVICE,
  GEOLOCATION_SERVICE,
  USER_AGENT_SERVICE,
  COOKIE_SERVICE
} from 'src/shared/constants/injection.tokens'

// ================================================================
// Types & Interfaces
// ================================================================
import { AuthError } from 'src/routes/auth/auth.error'
import { ICookieService, IDeviceService, ISessionService } from 'src/routes/auth/auth.types'
import { GetGroupedSessionsResponseSchema } from '../dtos/session.dto'
import { I18nTranslations } from 'src/generated/i18n.generated'
import { Device } from '@prisma/client'

// Infer the type for a single device session group from the Zod schema
type DeviceSessionGroup = z.infer<typeof GetGroupedSessionsResponseSchema.shape.devices.element>

/**
 * Service quản lý sessions và devices của người dùng
 * Cung cấp các chức năng xem, thu hồi, và quản lý sessions/devices
 */
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
    @Inject(DEVICE_SERVICE) private readonly deviceService: IDeviceService,
    private readonly redisService: RedisService,
    @Inject(USER_AGENT_SERVICE) private readonly userAgentService: UserAgentService,
    @Inject(COOKIE_SERVICE) private readonly cookieService: ICookieService
  ) {}

  // ================================================================
  // Public Methods - Session Management
  // ================================================================

  /**
   * Lấy danh sách sessions của user được nhóm theo device
   * Bao gồm thông tin device, location, và các session đang hoạt động
   * @param userId - ID của user
   * @param currentPage - Trang hiện tại (pagination)
   * @param itemsPerPage - Số item trên mỗi trang
   * @param currentSessionIdFromToken - ID session hiện tại từ token
   * @returns Danh sách sessions được nhóm theo device với pagination
   */
  async getSessions(
    userId: number,
    currentPage: number = 1,
    itemsPerPage: number = 5,
    currentSessionIdFromToken: string
  ): Promise<any> {
    this.logger.debug(
      `[getSessions] Getting grouped sessions for userId: ${userId}, page: ${currentPage}, limit: ${itemsPerPage}`
    )

    // Lấy tất cả sessions và devices của user
    const sessionResult = await this.sessionRepository.findSessionsByUserId(userId, { page: 1, limit: 1000 })
    let devices = await this.deviceRepository.findDevicesByUserId(userId)

    // Đảm bảo device hiện tại được include trong danh sách
    devices = await this.ensureCurrentDeviceIncluded(currentSessionIdFromToken, devices)

    const deviceGroups: DeviceSessionGroup[] = []

    // Tạo group cho mỗi device
    for (const device of devices) {
      const currentSessionDetails = await this.sessionRepository.findById(currentSessionIdFromToken)
      const isCurrentDevice = currentSessionDetails?.deviceId === device.id

      // Lọc sessions thuộc device này
      const deviceSessions = sessionResult.data.filter((session) => session.deviceId === device.id)

      if (deviceSessions.length === 0) continue

      const latestSession = deviceSessions[0]
      const deviceInfo = this.userAgentService.parse(latestSession?.userAgent)
      const activeSessionsCount = deviceSessions.filter((s) => s.isActive).length
      const lastActive = new Date(latestSession.lastActive)
      const locationResult = await this.getLocationFromIP(latestSession.ipAddress)

      // Xử lý thông tin chi tiết cho từng session
      const sessionItems = await Promise.all(
        deviceSessions.map(async (session) => {
          const sessionInfo = this.userAgentService.parse(session.userAgent)
          const inactiveDuration = session.isActive
            ? null
            : this.calculateInactiveDuration(new Date(session.lastActive))
          const sessionLocationResult = await this.getLocationFromIP(session.ipAddress)
          const isCurrentSession = session.id === currentSessionIdFromToken

          return {
            id: session.id,
            createdAt: new Date(session.createdAt),
            lastActive: new Date(session.lastActive),
            ipAddress: session.ipAddress,
            location: sessionLocationResult.display,
            browser: sessionInfo.browser,
            browserVersion: sessionInfo.browserVersion,
            app: sessionInfo.app,
            os: sessionInfo.os,
            osVersion: sessionInfo.osVersion,
            deviceType: sessionInfo.deviceType,
            isActive: session.isActive,
            inactiveDuration,
            isCurrentSession
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
        lastActive,
        location: locationResult.display,
        activeSessionsCount,
        isCurrentDevice,
        sessions: sessionItems
      })
    }

    // Sắp xếp theo thời gian active gần nhất
    deviceGroups.sort((a, b) => (b.lastActive?.getTime() || 0) - (a.lastActive?.getTime() || 0))

    // Áp dụng pagination
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

  /**
   * Đảm bảo device hiện tại được bao gồm trong danh sách devices
   * (có thể xảy ra trường hợp device không được trả về do phân quyền)
   */
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

  /**
   * Lấy thông tin địa lý từ địa chỉ IP
   */
  private async getLocationFromIP(ip: string): Promise<GeoLocationResult> {
    return this.geolocationService.getLocationFromIP(ip)
  }

  /**
   * Tính toán thời gian inactive của session và format thành string hiển thị
   * @param lastActiveDate - Thời điểm active cuối cùng
   * @returns Chuỗi mô tả thời gian inactive (vd: "5 minutes ago", "2 hours ago")
   */
  private calculateInactiveDuration(lastActiveDate: Date): string {
    const now = new Date()
    const diffSeconds = Math.round((now.getTime() - lastActiveDate.getTime()) / 1000)

    if (diffSeconds < 60) {
      return 'global.error.duration.justNow'
    }

    const diffMinutes = Math.round(diffSeconds / 60)
    if (diffMinutes === 1) {
      return 'global.error.duration.aMinuteAgo'
    }
    if (diffMinutes < 60) {
      return 'global.error.duration.minutesAgo'
    }

    const diffHours = Math.round(diffMinutes / 60)
    if (diffHours === 1) {
      return (this.i18nService as any).t('global.error.duration.anHourAgo')
    }
    if (diffHours < 24) {
      return (this.i18nService as any).t('global.error.duration.hoursAgo', { args: { count: diffHours } })
    }

    const diffDays = Math.round(diffHours / 24)
    if (diffDays === 1) {
      return (this.i18nService as any).t('global.error.duration.aDayAgo')
    }
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
    } else {
      this.logger.warn(`Could not send ${action} device trust email. User or device not found.`)
    }
  }

  async checkIfActionRequiresVerification(
    _userId: number,
    options: { sessionIds?: string[]; deviceIds?: number[] }
  ): Promise<boolean> {
    // If multiple devices/sessions are involved, always require verification
    if (options.deviceIds?.length) return true
    if (options.sessionIds && options.sessionIds.length > 1) return true

    if (options.sessionIds?.length === 1) {
      const session = await this.sessionRepository.findById(options.sessionIds[0])
      if (!session) return true // No session found, require verification

      const device = await this.deviceRepository.findById(session.deviceId)
      // If device is NOT trusted, require verification
      return !(device?.isTrusted ?? false)
    }

    // Default: require verification
    return true
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
  ): Promise<{ message: string; data: { revokedSessionsCount: number; untrustedDevicesCount: number } }> {
    let revokedSessionsCount = 0
    let untrustedDevicesCount = 0
    const excludeSessionId = options.excludeCurrentSession ? currentSessionContext.sessionId : undefined

    if (options.revokeAllUserSessions) {
      const result = await this.invalidateAllUserSessions(userId, undefined, excludeSessionId)
      revokedSessionsCount = result.deletedSessionsCount
      if (result.untrustedDeviceIds.length > 0) {
        untrustedDevicesCount = result.untrustedDeviceIds.length
      }
    } else {
      const untrustedDeviceIds = new Set<number>()

      if (options.sessionIds?.length) {
        for (const sessionId of options.sessionIds) {
          if (sessionId === excludeSessionId) continue
          const untrustedDeviceId = await this.revokeSingleSession(sessionId, userId)
          if (untrustedDeviceId) {
            untrustedDeviceIds.add(untrustedDeviceId)
          }
          revokedSessionsCount++
        }
      }
      if (options.deviceIds?.length) {
        for (const deviceId of options.deviceIds) {
          if (deviceId === currentSessionContext.deviceId && options.excludeCurrentSession) continue
          const result = await this.revokeDevice(deviceId, userId, excludeSessionId)
          revokedSessionsCount += result.revokedSessionsCount
          if (result.untrusted) {
            untrustedDeviceIds.add(deviceId)
          }
        }
      }
      untrustedDevicesCount = untrustedDeviceIds.size
    }

    // Sau khi thu hồi, đặt cờ yêu cầu xác minh lại cho người dùng
    if (revokedSessionsCount > 0) {
      await this.setReverifyFlagForUser(userId)
    }

    // Kiểm tra xem có revoke phiên hiện tại hay không, nếu có thì clear cookies
    const currentSessionRevoked = this.isCurrentSessionRevoked(options, currentSessionContext)
    if (currentSessionRevoked && res) {
      this.clearCurrentSessionCookies(res)
    }

    let message: string
    if (revokedSessionsCount > 0) {
      message = this.i18nService.t('auth.success.session.revokedCount', {
        args: { count: revokedSessionsCount }
      })
    } else {
      message = this.i18nService.t('auth.success.session.noSessionsToRevoke')
    }

    return {
      message,
      data: {
        revokedSessionsCount,
        untrustedDevicesCount
      }
    }
  }

  private async setReverifyFlagForUser(userId: number): Promise<void> {
    const key = RedisKeyManager.getUserReverifyNextLoginKey(userId)
    const ttl = 24 * 60 * 60 // 24 giờ
    await this.redisService.set(key, '1', 'EX', ttl)
    this.logger.log(`[setReverifyFlagForUser] Đã đặt cờ xác minh lại cho người dùng ${userId} với TTL ${ttl}s.`)
  }

  /**
   * Kiểm tra xem phiên hiện tại có bị revoke hay không
   */
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

    // Nếu excludeCurrentSession = true, thì không revoke phiên hiện tại
    if (excludeCurrentSession) {
      return false
    }

    // Nếu revokeAllUserSessions = true và không exclude current session
    if (revokeAllUserSessions) {
      return true
    }

    // Kiểm tra xem current session có trong danh sách sessionIds không
    if (sessionIds?.length && currentSessionId && sessionIds.includes(currentSessionId)) {
      return true
    }

    // Kiểm tra xem current device có trong danh sách deviceIds không
    if (deviceIds?.length && currentDeviceId && deviceIds.includes(currentDeviceId)) {
      return true
    }

    return false
  }

  /**
   * Clear cookies của phiên hiện tại (tương tự như logout)
   */
  private clearCurrentSessionCookies(res: Response): void {
    this.logger.log('[clearCurrentSessionCookies] Clearing cookies for current session due to revocation')

    // Xóa các cookie liên quan đến đăng nhập
    this.cookieService.clearTokenCookies(res)

    // Xóa SLT cookie nếu có
    this.cookieService.clearSltCookie(res)

    this.logger.log('[clearCurrentSessionCookies] Cookies cleared successfully')
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

    // Kiểm tra xem đó có phải là phiên cuối cùng trên thiết bị không
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

    // Notify user about the action
    await this.notifyDeviceTrustChange(userId, deviceId, 'untrusted')

    return { revokedSessionsCount: count, untrusted: true }
  }

  async updateDeviceName(userId: number, deviceId: number, name: string): Promise<{ message: string }> {
    const device = await this.deviceRepository.findById(deviceId)
    if (!device || device.userId !== userId) {
      throw AuthError.DeviceNotFound()
    }
    await this.deviceRepository.updateDeviceName(deviceId, name)
    return {
      message: 'auth.success.device.nameUpdated'
    }
  }

  async trustCurrentDevice(userId: number, deviceId: number): Promise<{ message: string }> {
    const device = await this.deviceRepository.findById(deviceId)
    if (!device || device.userId !== userId) {
      throw AuthError.DeviceNotFound()
    }
    await this.deviceRepository.updateDeviceTrustStatus(deviceId, true)
    await this.notifyDeviceTrustChange(userId, deviceId, 'trusted')
    return {
      message: 'auth.success.device.trusted'
    }
  }

  async untrustDevice(userId: number, deviceId: number): Promise<{ message: string }> {
    const device = await this.deviceRepository.findById(deviceId)
    if (!device || device.userId !== userId) {
      throw AuthError.DeviceNotFound()
    }
    await this.deviceRepository.updateDeviceTrustStatus(deviceId, false)
    await this.notifyDeviceTrustChange(userId, deviceId, 'untrusted')
    return {
      message: 'auth.success.device.untrusted'
    }
  }

  async isSessionInvalidated(sessionId: string): Promise<boolean> {
    const key = RedisKeyManager.getInvalidatedSessionsKey()
    return (await this.redisService.sismember(key, sessionId)) === 1
  }

  async invalidateSession(sessionId: string, reason?: string): Promise<void> {
    const key = RedisKeyManager.getInvalidatedSessionsKey()
    const sessionTtl = this.configService.get<number>('ABSOLUTE_SESSION_LIFETIME_MS', 30 * 24 * 60 * 60 * 1000)
    await this.redisService.sadd(key, sessionId)
    // It's good practice to set an expiration on the set itself,
    // though managing individual session expirations within the set can be complex.
    // For now, we rely on a global TTL for the whole set if it's created for the first time.
    await this.redisService.expire(key, sessionTtl / 1000)

    this.logger.log(`Session ${sessionId} invalidated. Reason: ${reason || 'Not specified'}.`)

    // To properly check permissions when revoking, we need the user ID.
    // Fetch the session data to get the associated userId.
    const session = await this.sessionRepository.findById(sessionId)

    // If the session doesn't exist (e.g., already deleted or invalid ID), we can't proceed.
    if (!session) {
      this.logger.warn(
        `[invalidateSession] Could not find session ${sessionId} to revoke. It might have been deleted already.`
      )
      return
    }

    // Now call revokeSingleSession with the correct userId.
    const deviceId = await this.revokeSingleSession(sessionId, session.userId, true)
    if (deviceId) {
      this.logger.log(`Session ${sessionId} was linked to device ${deviceId}.`)
    }
  }

  async invalidateAllUserSessions(
    userId: number,
    _reason?: string,
    sessionIdToExclude?: string
  ): Promise<{ deletedSessionsCount: number; untrustedDeviceIds: number[] }> {
    this.logger.warn(
      `Vô hiệu hóa tất cả các phiên cho người dùng ${userId}, ngoại trừ ${sessionIdToExclude ?? 'không có'}. Lý do: ${_reason ?? 'không rõ'}`
    )
    const { deletedSessionsCount, affectedDeviceIds } = await this.sessionRepository.deleteAllUserSessions(
      userId,
      sessionIdToExclude
    )

    const newlyUntrustedDeviceIds: number[] = []

    if (affectedDeviceIds.length > 0) {
      for (const deviceId of affectedDeviceIds) {
        const remainingSessionsOnDevice = await this.sessionRepository.countSessionsByDeviceId(deviceId)
        if (remainingSessionsOnDevice === 0) {
          // Giả sử deviceRepository.updateDeviceTrustStatus xử lý các trường hợp thiết bị không tồn tại
          // hoặc đã được bỏ tin cậy một cách nhẹ nhàng
          await this.deviceRepository.updateDeviceTrustStatus(deviceId, false)
          newlyUntrustedDeviceIds.push(deviceId)
        }
      }
      if (newlyUntrustedDeviceIds.length > 0) {
        this.logger.log(
          `[invalidateAllUserSessions] Đã bỏ tin cậy ${newlyUntrustedDeviceIds.length} thiết bị: ${newlyUntrustedDeviceIds.join(', ')}.`
        )
      }
    }

    return { deletedSessionsCount, untrustedDeviceIds: newlyUntrustedDeviceIds }
  }
}
