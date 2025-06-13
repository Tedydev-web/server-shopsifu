// NestJS core modules
import { Injectable, Logger, Inject } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { I18nService, I18nContext } from 'nestjs-i18n'

// External libraries
import { Device } from '@prisma/client'

// Internal services
import { PrismaService } from 'src/shared/providers/prisma/prisma.service'
import { GeolocationService } from 'src/shared/services/geolocation.service'
import { EmailService } from 'src/shared/services/email.service'
import { UserAgentService } from 'src/shared/services/user-agent.service'

// Repositories
import { DeviceRepository } from 'src/shared/repositories/device.repository'

// Types and interfaces
import { IDeviceService } from 'src/routes/auth/auth.types'
import { I18nTranslations } from 'src/generated/i18n.generated'
import { UserWithProfileAndRole } from 'src/routes/user/user.repository'

// Constants and utilities
import {
  EMAIL_SERVICE,
  GEOLOCATION_SERVICE,
  REDIS_SERVICE,
  USER_AGENT_SERVICE
} from 'src/shared/constants/injection.tokens'
import { DEVICE_REVERIFICATION_TTL } from 'src/shared/providers/redis/redis.constants'
import { RedisKeyManager } from 'src/shared/providers/redis/redis-keys.utils'

// Errors
import { GlobalError } from 'src/shared/global.error'
import { RedisService } from 'src/shared/services'
import { DeviceRiskLevel } from '../auth.constants'

export interface DeviceLocationData {
  city?: string
  country?: string
  latitude?: number
  longitude?: number
  accuracy?: number
  timestamp: number
}

export interface DeviceAnomalyData {
  deviceId: number
  userId: number
  riskLevel: DeviceRiskLevel
  anomalyType: string
  details: Record<string, any>
  timestamp: number
}

@Injectable()
export class DeviceService implements IDeviceService {
  private readonly logger = new Logger(DeviceService.name)
  private readonly maxAllowedDevices: number
  private readonly deviceTrustExpirationDays: number
  private readonly suspiciousLoginThreshold: number
  private readonly locationChangeThresholdKm: number
  private readonly deviceDataExpirationDays: number

  constructor(
    private readonly i18nService: I18nService<I18nTranslations>,
    private readonly configService: ConfigService,
    private readonly deviceRepository: DeviceRepository,
    @Inject(EMAIL_SERVICE) private readonly emailService: EmailService,
    @Inject(GEOLOCATION_SERVICE) private readonly geolocationService: GeolocationService,
    private readonly prisma: PrismaService,
    @Inject(USER_AGENT_SERVICE) private readonly userAgentService: UserAgentService,
    @Inject(REDIS_SERVICE) private readonly redisService: RedisService
  ) {
    this.maxAllowedDevices = this.configService.get<number>('MAX_DEVICES_PER_USER', 10)
    this.deviceTrustExpirationDays = this.configService.get<number>('DEVICE_TRUST_EXPIRATION_DAYS', 30)
    this.suspiciousLoginThreshold = this.configService.get<number>('SUSPICIOUS_LOGIN_THRESHOLD', 5)
    this.locationChangeThresholdKm = this.configService.get<number>('LOCATION_CHANGE_THRESHOLD_KM', 500)
    this.deviceDataExpirationDays = this.configService.get<number>('DEVICE_DATA_EXPIRATION_DAYS', 90)
  }

  async findById(deviceId: number): Promise<Device | null> {
    return this.deviceRepository.findById(deviceId)
  }

  async updateDeviceTrustStatus(deviceId: number, isTrusted: boolean): Promise<any> {
    return this.deviceRepository.updateDeviceTrustStatus(deviceId, isTrusted)
  }

  async isDeviceTrustValid(deviceId: number): Promise<boolean> {
    return this.deviceRepository.isDeviceTrustValid(deviceId)
  }

  async notifyLoginOnUntrustedDevice(
    user: UserWithProfileAndRole,
    deviceId: number,
    ipAddress?: string,
    userAgent?: string
  ): Promise<void> {
    try {
      if (!user) {
        return
      }

      const device = await this.deviceRepository.findById(deviceId)
      // Ngăn chặn việc gửi email liên tục cho cùng một sự kiện đăng nhập.
      // Nếu một thông báo đã được gửi trong vòng 5 phút qua, hãy bỏ qua.
      if (device && device.lastNotificationSentAt) {
        const lastSent = new Date(device.lastNotificationSentAt).getTime()
        if (Date.now() - lastSent < 5 * 60 * 1000) {
          return
        }
      }

      const locationResult = await this.geolocationService.getLocationFromIP(ipAddress ?? '')
      const location = locationResult.display

      const uaInfo = this.userAgentService.parse(userAgent)

      const lang = I18nContext.current()?.lang ?? 'vi'
      const localeForDate = lang === 'vi' ? 'vi-VN' : 'en-US'

      // Construct a more detailed device string
      let deviceString = [uaInfo.deviceVendor, uaInfo.deviceModel].filter(Boolean).join(' ') || 'Unknown Device'
      if (uaInfo.deviceType && deviceString === 'Unknown Device') {
        deviceString = uaInfo.deviceType
      }

      const details = [
        {
          label: 'email.Email.common.details.time',
          value: new Date().toLocaleString(localeForDate, {
            timeZone: locationResult.timezone || 'Asia/Ho_Chi_Minh',
            dateStyle: 'full',
            timeStyle: 'long'
          })
        },
        {
          label: 'email.Email.common.details.ipAddress',
          value: ipAddress ?? 'N/A'
        },
        {
          label: 'email.Email.common.details.location',
          value: location
        },
        {
          label: 'email.Email.common.details.device',
          value: deviceString
        },
        {
          label: 'email.Email.common.details.browser',
          value: [uaInfo.browser, uaInfo.browserVersion].filter(Boolean).join(' ') || 'N/A'
        },
        {
          label: 'email.Email.common.details.os',
          value: [uaInfo.os, uaInfo.osVersion].filter(Boolean).join(' ') || 'N/A'
        }
      ]

      await this.emailService.sendNewDeviceLoginEmail(user.email, {
        userName: user.userProfile?.username ?? user.email,
        details
      })

      // Cập nhật thời gian thông báo cuối
      await this.deviceRepository.updateLastNotificationSent(deviceId)
    } catch (error) {
      throw GlobalError.InternalServerError('auth.error.device.notifyLoginOnUntrustedDeviceFailed', {
        error: error.message
      })
    }
  }

  async getUserSuspiciousDevices(userId: number): Promise<Device[]> {
    // Lấy danh sách thiết bị của người dùng
    const userDevices = await this.deviceRepository.findDevicesByUserId(userId)
    const suspiciousDevices: Device[] = []

    // Kiểm tra từng thiết bị có phải là thiết bị đáng ngờ không
    for (const device of userDevices) {
      const key = `device:${device.id}:suspicious`
      const isSuspicious = (await this.redisService.exists(key)) > 0

      if (isSuspicious) {
        suspiciousDevices.push(device)
      }
    }

    return suspiciousDevices
  }

  async markDeviceAsSafe(deviceId: number, userId: number): Promise<void> {
    const device = await this.deviceRepository.findById(deviceId)

    if (!device || device.userId !== userId) {
      throw GlobalError.NotFound('device')
    }

    // Xóa đánh dấu đáng ngờ
    const suspiciousKey = RedisKeyManager.getDeviceSuspiciousKey(deviceId)
    await this.redisService.del(suspiciousKey)
  }

  async warnAboutDeviceLimit(user: UserWithProfileAndRole): Promise<boolean> {
    const userDevices = await this.deviceRepository.findDevicesByUserId(user.id)

    // Nếu số lượng thiết bị đã đạt 80% giới hạn
    if (userDevices.length >= Math.floor(this.maxAllowedDevices * 0.8)) {
      if (user) {
        // Kiểm tra đã cảnh báo gần đây chưa
        const warningKey = `user:${user.id}:device_limit_warning`
        const lastWarning = await this.redisService.get(warningKey)

        if (!lastWarning) {
          await this.emailService.sendDeviceLimitWarningEmail(user.email, {
            userName: user.userProfile?.username || user.email.split('@')[0],
            details: [
              {
                label: 'email.Email.common.details.currentDevices',
                value: `${userDevices.length}`
              },
              {
                label: 'email.Email.common.details.deviceLimit',
                value: `${this.maxAllowedDevices}`
              }
            ]
          })

          // Đánh dấu đã cảnh báo (trong 7 ngày)
          await this.redisService.set(warningKey, Date.now().toString(), 'EX', 60 * 60 * 24 * 7)

          return true
        }
      }
    }

    return false
  }

  async markDeviceForReverification(userId: number, deviceId: number, reasonInput: string): Promise<void> {
    const reverificationKey = RedisKeyManager.getDeviceReverificationKey(deviceId)
    await this.redisService.set(reverificationKey, reasonInput, 'EX', DEVICE_REVERIFICATION_TTL)
  }

  async checkDeviceNeedsReverification(userId: number, deviceId: number): Promise<boolean> {
    const reverificationKey = RedisKeyManager.getDeviceReverificationKey(deviceId)
    const needsReverification = await this.redisService.exists(reverificationKey)
    return needsReverification > 0
  }

  async clearDeviceReverification(userId: number, deviceId: number): Promise<void> {
    const reverificationKey = RedisKeyManager.getDeviceReverificationKey(deviceId)
    await this.redisService.del(reverificationKey)
  }
}
