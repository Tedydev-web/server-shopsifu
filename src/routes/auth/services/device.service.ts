import { Injectable, Logger, Inject } from '@nestjs/common'
import { I18nService, I18nContext } from 'nestjs-i18n'
import { ConfigService } from '@nestjs/config'
import { Device } from '@prisma/client'
import { PrismaService } from 'src/shared/services/prisma.service'
import { GeolocationService } from 'src/shared/services/geolocation.service'
import { RedisService } from 'src/shared/services/redis.service'
import { EMAIL_SERVICE, GEOLOCATION_SERVICE, USER_AGENT_SERVICE } from 'src/shared/constants/injection.tokens'
import { EmailService } from 'src/shared/services/email.service'
import { DeviceRepository } from 'src/shared/repositories/device.repository'
import { DEVICE_REVERIFICATION_TTL } from 'src/shared/constants/redis.constants'
import { IDeviceService } from 'src/routes/auth/auth.types'
import { RedisKeyManager } from 'src/shared/utils/redis-keys.utils'
import { UserAgentService } from 'src/shared/services/user-agent.service'
import { GlobalError } from 'src/shared/global.error'
import { I18nTranslations } from 'src/generated/i18n.generated'
import { UserWithProfileAndRole } from 'src/routes/user/user.repository'

/**
 * Kết quả đánh giá rủi ro thiết bị
 */
export enum DeviceRiskLevel {
  LOW = 'LOW',
  MEDIUM = 'MEDIUM',
  HIGH = 'HIGH'
}

/**
 * Dữ liệu về vị trí thiết bị
 */
export interface DeviceLocationData {
  city?: string
  country?: string
  latitude?: number
  longitude?: number
  accuracy?: number
  timestamp: number
}

/**
 * Thông tin bất thường về thiết bị
 */
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
    private readonly redisService: RedisService,
    private readonly i18nService: I18nService<I18nTranslations>,
    private readonly configService: ConfigService,
    private readonly deviceRepository: DeviceRepository,
    @Inject(EMAIL_SERVICE) private readonly emailService: EmailService,
    @Inject(GEOLOCATION_SERVICE) private readonly geolocationService: GeolocationService,
    private readonly prisma: PrismaService,
    @Inject(USER_AGENT_SERVICE) private readonly userAgentService: UserAgentService
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

  /**
   * Gửi email thông báo cho người dùng về việc đăng nhập thành công
   * trên một thiết bị chưa được tin cậy.
   * Phương thức này được gọi sau khi quá trình xác thực hoàn tất.
   */
  async notifyLoginOnUntrustedDevice(
    user: UserWithProfileAndRole,
    deviceId: number,
    ipAddress?: string,
    userAgent?: string
  ): Promise<void> {
    try {
      if (!user) {
        this.logger.warn(`[notifyLoginOnUntrustedDevice] User not found`)
        return
      }

      const device = await this.deviceRepository.findById(deviceId)
      // Ngăn chặn việc gửi email liên tục cho cùng một sự kiện đăng nhập.
      // Nếu một thông báo đã được gửi trong vòng 5 phút qua, hãy bỏ qua.
      if (device && device.lastNotificationSentAt) {
        const lastSent = new Date(device.lastNotificationSentAt).getTime()
        if (Date.now() - lastSent < 5 * 60 * 1000) {
          this.logger.debug(
            `[notifyLoginOnUntrustedDevice] Notification sent recently for device ${deviceId}. Skipping.`
          )
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
          label: this.i18nService.t('email.Email.common.details.time', { lang }),
          value: new Date().toLocaleString(localeForDate, {
            timeZone: locationResult.timezone || 'Asia/Ho_Chi_Minh',
            dateStyle: 'full',
            timeStyle: 'long'
          })
        },
        {
          label: this.i18nService.t('email.Email.common.details.ipAddress', { lang }),
          value: ipAddress ?? 'N/A'
        },
        {
          label: this.i18nService.t('email.Email.common.details.location', { lang }),
          value: location
        },
        {
          label: this.i18nService.t('email.Email.common.details.device', { lang }),
          value: deviceString
        },
        {
          label: this.i18nService.t('email.Email.common.details.browser', { lang }),
          value: [uaInfo.browser, uaInfo.browserVersion].filter(Boolean).join(' ') || 'N/A'
        },
        {
          label: this.i18nService.t('email.Email.common.details.os', { lang }),
          value: [uaInfo.os, uaInfo.osVersion].filter(Boolean).join(' ') || 'N/A'
        }
      ]

      await this.emailService.sendNewDeviceLoginEmail(user.email, {
        userName: user.userProfile?.username ?? user.email,
        details
      })

      // Cập nhật thời gian thông báo cuối
      await this.deviceRepository.updateLastNotificationSent(deviceId)

      this.logger.log(
        `[notifyLoginOnUntrustedDevice] Sent new device login notification to user ${user.id} for device ${deviceId}`
      )
    } catch (error) {
      this.logger.error(
        `[notifyLoginOnUntrustedDevice] Failed to send notification for user ${user.id}. Error: ${error.message}`,
        error.stack
      )
    }
  }

  /**
   * Lấy danh sách thiết bị đáng ngờ của người dùng
   */
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

  /**
   * Đánh dấu thiết bị là an toàn (bỏ đánh dấu đáng ngờ)
   */
  async markDeviceAsSafe(deviceId: number, userId: number): Promise<void> {
    const device = await this.deviceRepository.findById(deviceId)

    if (!device || device.userId !== userId) {
      throw GlobalError.NotFound('device')
    }

    // Xóa đánh dấu đáng ngờ
    const suspiciousKey = RedisKeyManager.getDeviceSuspiciousKey(deviceId)
    await this.redisService.del(suspiciousKey)

    this.logger.debug(`[markDeviceAsSafe] Đã đánh dấu thiết bị ${deviceId} là an toàn`)
  }

  /**
   * Cảnh báo về thiết bị khi số lượng thiết bị của người dùng gần đạt giới hạn
   */
  async warnAboutDeviceLimit(user: UserWithProfileAndRole): Promise<boolean> {
    const userDevices = await this.deviceRepository.findDevicesByUserId(user.id)

    // Nếu số lượng thiết bị đã đạt 80% giới hạn
    if (userDevices.length >= Math.floor(this.maxAllowedDevices * 0.8)) {
      if (user) {
        // Kiểm tra đã cảnh báo gần đây chưa
        const warningKey = `user:${user.id}:device_limit_warning`
        const lastWarning = await this.redisService.get(warningKey)

        if (!lastWarning) {
          const lang = I18nContext.current()?.lang ?? 'vi'
          // Gửi email cảnh báo
          await this.emailService.sendDeviceLimitWarningEmail(user.email, {
            userName: user.userProfile?.username || user.email.split('@')[0],
            details: [
              {
                label: this.i18nService.t('email.Email.common.details.currentDevices', { lang }),
                value: `${userDevices.length}`
              },
              {
                label: this.i18nService.t('email.Email.common.details.deviceLimit', { lang }),
                value: `${this.maxAllowedDevices}`
              }
            ]
          })

          // Đánh dấu đã cảnh báo (trong 7 ngày)
          await this.redisService.set(warningKey, Date.now().toString(), 'EX', 60 * 60 * 24 * 7)

          this.logger.debug(`[warnAboutDeviceLimit] Đã cảnh báo userId ${user.id} về giới hạn thiết bị`)
          return true
        }
      }
    }

    return false
  }

  /**
   * Đánh dấu một thiết bị cần xác minh lại
   */
  async markDeviceForReverification(userId: number, deviceId: number, reasonInput: string): Promise<void> {
    const reverificationKey = RedisKeyManager.getDeviceReverificationKey(deviceId)
    await this.redisService.set(reverificationKey, reasonInput, 'EX', DEVICE_REVERIFICATION_TTL)
    this.logger.log(`Device ${deviceId} for user ${userId} marked for reverification. Reason: ${reasonInput}`)
  }

  /**
   * Kiểm tra xem một thiết bị có cần xác minh lại không
   */
  async checkDeviceNeedsReverification(userId: number, deviceId: number): Promise<boolean> {
    const reverificationKey = RedisKeyManager.getDeviceReverificationKey(deviceId)
    const needsReverification = await this.redisService.exists(reverificationKey)
    return needsReverification > 0
  }

  /**
   * Xóa cờ đánh dấu cần xác minh lại cho thiết bị
   */
  async clearDeviceReverification(userId: number, deviceId: number): Promise<void> {
    const reverificationKey = RedisKeyManager.getDeviceReverificationKey(deviceId)
    await this.redisService.del(reverificationKey)
    this.logger.log(`Cleared reverification flag for device ${deviceId} of user ${userId}.`)
  }
}
