import { Injectable, Logger, Inject } from '@nestjs/common'
import { I18nService } from 'nestjs-i18n'
import { AuthError } from 'src/routes/auth/auth.error'
import { ConfigService } from '@nestjs/config'
import { IDeviceService, ISessionService } from 'src/shared/types/auth.types'
import {
  DEVICE_SERVICE,
  EMAIL_SERVICE,
  GEOLOCATION_SERVICE,
  USER_AGENT_SERVICE
} from 'src/shared/constants/injection.tokens'
import { PrismaService } from 'src/shared/services/prisma.service'
import { GetGroupedSessionsResponseDto, GetGroupedSessionsResponseSchema } from '../dtos/session.dto'
import { GeolocationService } from 'src/shared/services/geolocation.service'
import { SessionRepository, DeviceRepository } from 'src/routes/auth/repositories'
import { Device } from '@prisma/client'
import { RedisService } from 'src/shared/services/redis.service'
import { RedisKeyManager } from 'src/shared/utils/redis-keys.utils'
import { z } from 'zod'
import { EmailService } from 'src/shared/services/email.service'
import { GeoLocationResult } from 'src/shared/services/geolocation.service'
import { UserAgentService } from '../../../shared/services/user-agent.service'

// Infer the type for a single device session group from the Zod schema
type DeviceSessionGroup = z.infer<typeof GetGroupedSessionsResponseSchema.shape.data.element>

@Injectable()
export class SessionsService implements ISessionService {
  private readonly logger = new Logger(SessionsService.name)

  constructor(
    private readonly i18nService: I18nService,
    private readonly configService: ConfigService,
    private readonly sessionRepository: SessionRepository,
    private readonly deviceRepository: DeviceRepository,
    @Inject(EMAIL_SERVICE) private readonly emailService: EmailService,
    private readonly prismaService: PrismaService,
    @Inject(GEOLOCATION_SERVICE) private readonly geolocationService: GeolocationService,
    @Inject(DEVICE_SERVICE) private readonly deviceService: IDeviceService,
    private readonly redisService: RedisService,
    @Inject(USER_AGENT_SERVICE) private readonly userAgentService: UserAgentService
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

    const deviceGroups: DeviceSessionGroup[] = []

    for (const device of devices) {
      const currentSessionDetails = await this.sessionRepository.findById(currentSessionIdFromToken)
      const isCurrentDevice = currentSessionDetails?.deviceId === device.id

      const deviceSessions = sessionResult.data.filter((session) => session.deviceId === device.id)

      if (deviceSessions.length === 0) continue

      const latestSession = deviceSessions[0]
      const deviceInfo = this.userAgentService.parse(latestSession?.userAgent)
      const activeSessionsCount = deviceSessions.filter((s) => s.isActive).length
      const lastActive = new Date(latestSession.lastActive)
      const locationResult = await this.getLocationFromIP(latestSession.ipAddress)

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
        location: locationResult.display,
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
      data: paginatedDeviceGroups,
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

  private async getLocationFromIP(ip: string): Promise<GeoLocationResult> {
    if (!ip) return { display: 'Unknown' }
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
          label: this.i18nService.t('email.Email.common.details.device'),
          value: `${deviceInfo.browser} on ${deviceInfo.os}`
        },
        {
          label: this.i18nService.t('email.Email.common.details.ipAddress'),
          value: device.lastKnownIp ?? 'N/A'
        },
        {
          label: this.i18nService.t('email.Email.common.details.location'),
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

    const messageKey =
      revokedSessionsCount > 0 ? 'auth.Auth.Session.RevokedSuccessfullyCount' : 'auth.Auth.Session.NoSessionsToRevoke'
    const i18nMessage = this.i18nService.t(messageKey, {
      args: { count: revokedSessionsCount }
    })
    const message = typeof i18nMessage === 'string' ? i18nMessage : 'Sessions have been revoked.'

    return { message, revokedSessionsCount, untrustedDevicesCount }
  }

  private async setReverifyFlagForUser(userId: number): Promise<void> {
    const key = RedisKeyManager.getUserReverifyNextLoginKey(userId)
    const ttl = 24 * 60 * 60 // 24 giờ
    await this.redisService.set(key, '1', 'EX', ttl)
    this.logger.log(`[setReverifyFlagForUser] Đã đặt cờ xác minh lại cho người dùng ${userId} với TTL ${ttl}s.`)
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
      this.logger.log(
        `[revokeSingleSession] Phiên cuối cùng của thiết bị ${deviceId} đã bị thu hồi. Bỏ tin cậy thiết bị.`
      )
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
      throw AuthError.DeviceNotOwnedByUser()
    }

    const { count: revokedCount } = await this.sessionRepository.deleteSessionsByDeviceId(deviceId, excludeSessionId)

    // Luôn bỏ tin cậy thiết bị khi nó bị thu hồi một cách rõ ràng
    let wasUntrusted = false
    if (device.isTrusted) {
      await this.deviceRepository.updateDeviceTrustStatus(deviceId, false)
      wasUntrusted = true
    }

    this.logger.log(`[revokeDevice] Đã thu hồi ${revokedCount} phiên cho thiết bị ${deviceId} và bỏ tin cậy nó.`)

    return { revokedSessionsCount: revokedCount, untrusted: wasUntrusted }
  }

  async updateDeviceName(userId: number, deviceId: number, name: string): Promise<void> {
    const device = await this.deviceRepository.findById(deviceId)
    if (!device || device.userId !== userId) {
      throw AuthError.DeviceNotFound()
    }
    await this.deviceRepository.updateDeviceName(deviceId, name)
  }

  async trustCurrentDevice(userId: number, deviceId: number): Promise<void> {
    await this.deviceRepository.updateDeviceTrustStatus(deviceId, true)
    await this.notifyDeviceTrustChange(userId, deviceId, 'trusted')
  }

  async untrustDevice(userId: number, deviceId: number): Promise<void> {
    await this.deviceRepository.updateDeviceTrustStatus(deviceId, false)
    await this.notifyDeviceTrustChange(userId, deviceId, 'untrusted')
  }

  async isSessionInvalidated(sessionId: string): Promise<boolean> {
    const session = await this.sessionRepository.findById(sessionId)
    return !session
  }

  async invalidateSession(sessionId: string, reason?: string): Promise<void> {
    const session = await this.sessionRepository.findById(sessionId)
    if (session) {
      this.logger.debug(`[invalidateSession] Vô hiệu hóa phiên ${sessionId} cho người dùng ${session.userId}.`)
      // Xác định nếu đây là thao tác logout
      const isLogout = reason === 'logout'
      await this.revokeSingleSession(sessionId, session.userId, isLogout)

      // Chỉ đặt cờ yêu cầu xác minh lại nếu đây không phải là một thao tác đăng xuất thông thường
      if (!isLogout) {
        await this.setReverifyFlagForUser(session.userId)
      }
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
