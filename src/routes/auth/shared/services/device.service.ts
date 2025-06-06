import { Injectable, Logger, Inject } from '@nestjs/common'
import { I18nService } from 'nestjs-i18n'
import { ConfigService } from '@nestjs/config'
import { Device } from '@prisma/client'
import { PrismaService } from 'src/shared/services/prisma.service'
import { GeolocationService } from 'src/routes/auth/shared/services/common/geolocation.service'
import { RedisService } from 'src/providers/redis/redis.service'
import { EMAIL_SERVICE, GEOLOCATION_SERVICE, REDIS_SERVICE } from 'src/shared/constants/injection.tokens'
import { EmailService, SecurityAlertType } from 'src/routes/auth/shared/services/common/email.service'
import { DeviceRepository, UserAuthRepository } from 'src/routes/auth/shared/repositories'
import { DEVICE_REVERIFY_KEY_PREFIX, DEVICE_REVERIFICATION_TTL } from '../../shared/constants/auth.constants'
import { IDeviceService } from 'src/routes/auth/shared/auth.types'
import { isNullOrUndefined } from 'src/shared/utils/type-guards.utils'
import { RedisKeyManager } from 'src/shared/utils/redis-keys.utils'

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
    @Inject(REDIS_SERVICE) private readonly redisService: RedisService,
    private readonly i18nService: I18nService,
    private readonly configService: ConfigService,
    private readonly deviceRepository: DeviceRepository,
    @Inject(EMAIL_SERVICE) private readonly emailService: EmailService,
    @Inject(GEOLOCATION_SERVICE) private readonly geolocationService: GeolocationService,
    private readonly userAuthRepository: UserAuthRepository,
    private readonly prisma: PrismaService
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
   * Xử lý đăng nhập trên thiết bị và phát hiện bất thường
   */
  async processDeviceLogin(
    userId: number,
    deviceId: number,
    ipAddress: string,
    userAgent: string
  ): Promise<{
    isNewDevice: boolean
    isSuspicious: boolean
    riskLevel: DeviceRiskLevel
    location: string
  }> {
    this.logger.debug(`[processDeviceLogin] userId=${userId}, deviceId=${deviceId}, ipAddress=${ipAddress}`)

    // Lấy vị trí từ IP
    const locationString = await this.geolocationService.getLocationFromIP(ipAddress)
    const now = new Date()

    // Lưu thông tin địa lý mới nhất của thiết bị
    const deviceLocationKey = `device:${deviceId}:locations`
    await this.redisService.lpush(
      deviceLocationKey,
      JSON.stringify({
        location: locationString,
        ipAddress,
        timestamp: now.getTime()
      })
    )
    await this.redisService.ltrim(deviceLocationKey, 0, 19) // Giữ 20 vị trí gần nhất

    // Cập nhật thông tin thiết bị
    await this.deviceRepository.updateDeviceLocation(deviceId, {
      lastKnownIp: ipAddress,
      lastKnownCountry: locationString.split(', ')[1] || locationString,
      lastKnownCity: locationString.split(', ')[0] || 'Unknown'
    })

    // Kiểm tra mức độ rủi ro
    const riskLevel = await this.assessDeviceRisk(deviceId, userId, ipAddress, userAgent)
    const isNewDevice = await this.isNewDevice(deviceId)

    // Kiểm tra có đáng ngờ không
    const isSuspicious = riskLevel === DeviceRiskLevel.HIGH

    // Gửi thông báo nếu thiết bị mới hoặc đáng ngờ
    if (isNewDevice) {
      await this.notifyUserAboutNewDevice(userId, deviceId, ipAddress, userAgent, locationString, riskLevel)
    } else if (isSuspicious) {
      await this.notifySuspiciousLogin(userId, deviceId, ipAddress, userAgent, locationString, riskLevel)
    }

    return {
      isNewDevice,
      isSuspicious,
      riskLevel,
      location: locationString
    }
  }

  /**
   * Đánh giá mức độ rủi ro của thiết bị
   */
  private async assessDeviceRisk(
    deviceId: number,
    userId: number,
    ipAddress: string,
    userAgent: string
  ): Promise<DeviceRiskLevel> {
    let riskScore = 0
    const anomalyFactors: string[] = []

    // 1. Kiểm tra lịch sử vị trí
    const locationAnomaly = await this.detectLocationAnomaly(deviceId, ipAddress)
    if (locationAnomaly) {
      riskScore += 30
      anomalyFactors.push('LOCATION_CHANGE')
    }

    // 2. Kiểm tra tần suất đăng nhập thất bại
    const loginFailCount = await this.getRecentLoginFailures(userId)
    if (loginFailCount > 0) {
      riskScore += Math.min(loginFailCount * 5, 25)
      anomalyFactors.push('RECENT_LOGIN_FAILURES')
    }

    // 3. Kiểm tra thời gian đăng nhập bất thường
    const timeAnomaly = this.detectTimeAnomaly(userId)
    if (timeAnomaly) {
      riskScore += 15
      anomalyFactors.push('UNUSUAL_LOGIN_TIME')
    }

    // 4. Thiết bị có phải là thiết bị đáng ngờ
    const isKnownSuspiciousDevice = await this.isSuspiciousDevice(deviceId)
    if (isKnownSuspiciousDevice) {
      riskScore += 40
      anomalyFactors.push('KNOWN_SUSPICIOUS_DEVICE')
    }

    // Lưu thông tin đánh giá rủi ro
    if (anomalyFactors.length > 0) {
      await this.saveDeviceRiskAssessment(deviceId, userId, {
        riskScore,
        anomalyFactors,
        ipAddress,
        timestamp: Date.now(),
        deviceId,
        userId
      })
    }

    // Xác định mức độ rủi ro
    if (riskScore >= 50) {
      return DeviceRiskLevel.HIGH
    } else if (riskScore >= 25) {
      return DeviceRiskLevel.MEDIUM
    } else {
      return DeviceRiskLevel.LOW
    }
  }

  /**
   * Kiểm tra xem thiết bị có phải là thiết bị mới không
   */
  private async isNewDevice(deviceId: number): Promise<boolean> {
    const device = await this.deviceRepository.findById(deviceId)
    if (!device) return true

    // Nếu thiết bị vừa được tạo (thời gian tạo gần với thời gian cập nhật)
    const createdDate = new Date(device.createdAt)
    const now = new Date()
    const diffMinutes = (now.getTime() - createdDate.getTime()) / (1000 * 60)

    return diffMinutes < 5 // Coi là thiết bị mới nếu được tạo trong vòng 5 phút
  }

  /**
   * Phát hiện bất thường về vị trí
   */
  private async detectLocationAnomaly(deviceId: number, currentIp: string): Promise<boolean> {
    // Lấy lịch sử vị trí của thiết bị
    const locationHistoryKey = `device:${deviceId}:locations`
    const locationHistory = await this.redisService.lrange(locationHistoryKey, 0, 5)

    if (!locationHistory || locationHistory.length <= 1) {
      return false // Không đủ dữ liệu để so sánh
    }

    // Lấy vị trí hiện tại
    const currentLocation = await this.geolocationService.getLocationFromIP(currentIp)

    // So sánh với vị trí trước đó (trừ vị trí hiện tại)
    for (let i = 1; i < locationHistory.length; i++) {
      try {
        const previousLocationData = JSON.parse(locationHistory[i])
        const previousLocation = previousLocationData?.location

        // Kiểm tra sự thay đổi quốc gia
        if (previousLocation && currentLocation !== previousLocation) {
          const currentCountry = currentLocation.split(', ')[1] || currentLocation
          const previousCountry = previousLocation.split(', ')[1] || previousLocation

          // Nếu khác quốc gia và thời gian gần nhau, coi là bất thường
          if (currentCountry !== previousCountry) {
            const timeDiff = Date.now() - (previousLocationData?.timestamp || 0)
            const hoursDiff = timeDiff / (1000 * 60 * 60)

            // Bất thường nếu thay đổi quốc gia trong vòng 12 giờ
            if (hoursDiff < 12) {
              return true
            }
          }
        }
      } catch (error) {
        this.logger.error(`[detectLocationAnomaly] Lỗi khi phân tích dữ liệu vị trí: ${error.message}`)
      }
    }

    return false
  }

  /**
   * Lấy số lần đăng nhập thất bại gần đây
   */
  private async getRecentLoginFailures(userId: number): Promise<number> {
    const failureKey = `user:${userId}:login_failures`
    const recentFailures = await this.redisService.get(failureKey)
    return recentFailures ? parseInt(recentFailures, 10) : 0
  }

  /**
   * Kiểm tra thời gian đăng nhập bất thường
   */
  private detectTimeAnomaly(userId: number): boolean {
    // Phát hiện đăng nhập vào thời điểm bất thường (như giữa đêm)
    const hour = new Date().getHours()
    return hour >= 1 && hour <= 4 // Giữa 1h sáng và 4h sáng
  }

  /**
   * Kiểm tra thiết bị đã từng được đánh dấu là đáng ngờ
   */
  private async isSuspiciousDevice(deviceId: number): Promise<boolean> {
    const key = `device:${deviceId}:suspicious`
    return (await this.redisService.exists(key)) > 0
  }

  /**
   * Lưu đánh giá rủi ro thiết bị
   */
  private async saveDeviceRiskAssessment(deviceId: number, userId: number, assessmentData: any): Promise<void> {
    const key = `device:${deviceId}:risk_assessments`
    await this.redisService.lpush(key, JSON.stringify(assessmentData))
    await this.redisService.ltrim(key, 0, 9) // Giữ 10 đánh giá gần nhất

    // Nếu rủi ro cao, đánh dấu thiết bị là đáng ngờ
    if (assessmentData.riskScore >= 50) {
      const suspiciousKey = `device:${deviceId}:suspicious`
      await this.redisService.set(suspiciousKey, '1', 'EX', 60 * 60 * 24 * 7) // Đánh dấu trong 7 ngày
    }
  }

  /**
   * Thông báo cho user về việc đăng nhập từ thiết bị mới
   */
  private async notifyUserAboutNewDevice(
    userId: number,
    deviceId: number,
    ipAddress: string,
    userAgent: string,
    location: string,
    riskLevel: DeviceRiskLevel
  ): Promise<void> {
    try {
      const user = await this.userAuthRepository.findById(userId)
      if (!user) return

      // Kiểm tra thời gian thông báo cuối của thiết bị
      const device = await this.deviceRepository.findById(deviceId)
      if (device && device.lastNotificationSentAt) {
        const lastNotification = new Date(device.lastNotificationSentAt)
        const hoursSinceLastNotification = (Date.now() - lastNotification.getTime()) / (1000 * 60 * 60)

        // Nếu đã thông báo trong 24h qua, không gửi thêm
        if (hoursSinceLastNotification < 24) {
          this.logger.debug(`[notifyUserAboutNewDevice] Đã thông báo gần đây, bỏ qua`)
          return
        }
      }

      // Gửi email thông báo
      await this.emailService.sendSecurityAlertEmail(SecurityAlertType.LOGIN_FROM_NEW_DEVICE, user.email, {
        userName: user.userProfile?.firstName || user.email.split('@')[0],
        deviceName: device?.name || 'Thiết bị mới',
        deviceType: this.extractDeviceType(userAgent),
        browser: this.extractBrowserInfo(userAgent),
        ipAddress,
        location,
        time: new Date().toISOString(),
        riskLevel
      })

      // Cập nhật thời gian thông báo cuối
      await this.deviceRepository.updateLastNotificationSent(deviceId)

      this.logger.debug(`[notifyUserAboutNewDevice] Đã gửi thông báo thiết bị mới cho userId ${userId}`)
    } catch (error) {
      this.logger.error(`[notifyUserAboutNewDevice] Lỗi: ${error.message}`)
    }
  }

  /**
   * Thông báo về đăng nhập đáng ngờ
   */
  private async notifySuspiciousLogin(
    userId: number,
    deviceId: number,
    ipAddress: string,
    userAgent: string,
    location: string,
    riskLevel: DeviceRiskLevel
  ): Promise<void> {
    try {
      const user = await this.userAuthRepository.findById(userId)
      if (!user) return

      // Kiểm tra thời gian thông báo cuối của thiết bị
      const device = await this.deviceRepository.findById(deviceId)
      if (device && device.lastNotificationSentAt) {
        const lastNotification = new Date(device.lastNotificationSentAt)
        const hoursSinceLastNotification = (Date.now() - lastNotification.getTime()) / (1000 * 60 * 60)

        // Nếu đã thông báo trong 12h qua, không gửi thêm (thời gian ngắn hơn thông báo thông thường)
        if (hoursSinceLastNotification < 12) {
          this.logger.debug(`[notifySuspiciousLogin] Đã thông báo gần đây, bỏ qua`)
          return
        }
      }

      // Gửi email cảnh báo
      await this.emailService.sendSecurityAlertEmail(SecurityAlertType.LOGIN_FROM_NEW_DEVICE, user.email, {
        userName: user.userProfile?.firstName || user.email.split('@')[0],
        deviceName: device?.name || 'Thiết bị không xác định',
        deviceType: this.extractDeviceType(userAgent),
        browser: this.extractBrowserInfo(userAgent),
        ipAddress,
        location,
        time: new Date().toISOString(),
        riskLevel,
        isSuspicious: true,
        urgencyLevel: 'high'
      })

      // Cập nhật thời gian thông báo cuối
      await this.deviceRepository.updateLastNotificationSent(deviceId)

      this.logger.debug(`[notifySuspiciousLogin] Đã gửi cảnh báo đăng nhập đáng ngờ cho userId ${userId}`)
    } catch (error) {
      this.logger.error(`[notifySuspiciousLogin] Lỗi: ${error.message}`)
    }
  }

  /**
   * Trích xuất loại thiết bị từ user agent
   */
  private extractDeviceType(userAgent: string): string {
    if (!userAgent) return 'Unknown device'

    if (/iPad/i.test(userAgent)) {
      return 'iPad'
    } else if (/iPhone/i.test(userAgent)) {
      return 'iPhone'
    } else if (/Android.*Mobile/i.test(userAgent)) {
      return 'Android phone'
    } else if (/Android/i.test(userAgent)) {
      return 'Android tablet'
    } else if (/Windows Phone/i.test(userAgent)) {
      return 'Windows Phone'
    } else if (/Windows NT/i.test(userAgent)) {
      return 'Windows PC'
    } else if (/Macintosh/i.test(userAgent)) {
      return 'Mac'
    } else if (/Linux/i.test(userAgent)) {
      return 'Linux'
    }

    return 'Unknown device'
  }

  /**
   * Trích xuất thông tin trình duyệt từ user agent
   */
  private extractBrowserInfo(userAgent: string): string {
    if (!userAgent) return 'Unknown browser'

    if (/Edge/i.test(userAgent)) {
      return 'Microsoft Edge'
    } else if (/Chrome/i.test(userAgent)) {
      if (/Edg/i.test(userAgent)) {
        return 'Microsoft Edge'
      }
      return 'Google Chrome'
    } else if (/Firefox/i.test(userAgent)) {
      return 'Mozilla Firefox'
    } else if (/Safari/i.test(userAgent)) {
      return 'Safari'
    } else if (/Opera|OPR/i.test(userAgent)) {
      return 'Opera'
    } else if (/MSIE|Trident/i.test(userAgent)) {
      return 'Internet Explorer'
    }

    return 'Unknown browser'
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
      throw new Error('Không tìm thấy thiết bị hoặc thiết bị không thuộc về người dùng')
    }

    // Xóa đánh dấu đáng ngờ
    const suspiciousKey = `device:${device.id}:suspicious`
    await this.redisService.del(suspiciousKey)

    this.logger.debug(`[markDeviceAsSafe] Đã đánh dấu thiết bị ${deviceId} là an toàn`)
  }

  /**
   * Cảnh báo về thiết bị khi số lượng thiết bị của người dùng gần đạt giới hạn
   */
  async warnAboutDeviceLimit(userId: number): Promise<boolean> {
    const userDevices = await this.deviceRepository.findDevicesByUserId(userId)

    // Nếu số lượng thiết bị đã đạt 80% giới hạn
    if (userDevices.length >= Math.floor(this.maxAllowedDevices * 0.8)) {
      const user = await this.userAuthRepository.findById(userId)

      if (user) {
        // Kiểm tra đã cảnh báo gần đây chưa
        const warningKey = `user:${userId}:device_limit_warning`
        const lastWarning = await this.redisService.get(warningKey)

        if (!lastWarning) {
          // Gửi email cảnh báo
          await this.emailService.sendSecurityAlertEmail(SecurityAlertType.DEVICE_LIMIT_WARNING, user.email, {
            userName: user.userProfile?.firstName || user.email.split('@')[0],
            currentDeviceCount: userDevices.length,
            maxDevices: this.maxAllowedDevices
          })

          // Đánh dấu đã cảnh báo (trong 7 ngày)
          await this.redisService.set(warningKey, Date.now().toString(), 'EX', 60 * 60 * 24 * 7)

          this.logger.debug(`[warnAboutDeviceLimit] Đã cảnh báo userId ${userId} về giới hạn thiết bị`)
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
    const reason = reasonInput || 'UNKNOWN'
    this.logger.debug(
      `[markDeviceForReverification] Marking device ${deviceId} of user ${userId} for reverification. Reason: ${reason}`
    )
    const reverificationKey = RedisKeyManager.customKey(DEVICE_REVERIFY_KEY_PREFIX, deviceId.toString())
    await this.redisService.set(reverificationKey, 'true', 'EX', DEVICE_REVERIFICATION_TTL)
  }

  /**
   * Kiểm tra xem một thiết bị có cần xác minh lại không
   */
  async checkDeviceNeedsReverification(userId: number, deviceId: number): Promise<boolean> {
    const reverificationKey = RedisKeyManager.customKey(DEVICE_REVERIFY_KEY_PREFIX, deviceId.toString())
    const needsReverification = await this.redisService.get(reverificationKey)
    if (needsReverification === 'true') {
      this.logger.debug(
        `[checkDeviceNeedsReverification] Device ${deviceId} of user ${userId} requires reverification.`
      )
      return true
    }
    return false
  }

  /**
   * Xóa cờ đánh dấu cần xác minh lại cho thiết bị
   */
  async clearDeviceReverification(userId: number, deviceId: number): Promise<void> {
    this.logger.debug(
      `[clearDeviceReverification] Clearing reverification flag for device ${deviceId} of user ${userId}.`
    )
    const reverificationKey = RedisKeyManager.customKey(DEVICE_REVERIFY_KEY_PREFIX, deviceId.toString())
    await this.redisService.del(reverificationKey)
  }
}
