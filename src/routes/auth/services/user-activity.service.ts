// ================================================================
// NestJS Dependencies
// ================================================================
import { Injectable, Logger, Inject } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { I18nService, I18nContext } from 'nestjs-i18n'

// ================================================================
// External Libraries
// ================================================================

// ================================================================
// Internal Services & Types
// ================================================================
import { RedisService } from 'src/shared/providers/redis/redis.service'
import { RedisKeyManager } from 'src/shared/providers/redis/redis-keys.utils'
import { EmailService } from 'src/shared/services/email.service'
import { GeolocationService, GeoLocationResult } from 'src/shared/services/geolocation.service'
import { UserAgentService } from 'src/shared/services/user-agent.service'
import { calculateDistance, Coordinates } from 'src/shared/utils/geolocation.utils'

// ================================================================
// Repositories
// ================================================================
import { UserRepository, UserWithProfileAndRole } from 'src/routes/user/user.repository'

// ================================================================
// Constants & Injection Tokens
// ================================================================
import {
  EMAIL_SERVICE,
  GEOLOCATION_SERVICE,
  REDIS_SERVICE,
  USER_AGENT_SERVICE
} from 'src/shared/constants/injection.tokens'

// ================================================================
// Types & Interfaces
// ================================================================
import { I18nTranslations } from 'src/generated/i18n.generated'
import { ActivitySeverity, UserActivityType } from '../auth.constants'

export interface UserActivity {
  userId: number
  type: UserActivityType
  timestamp: number
  ipAddress?: string
  userAgent?: string
  deviceId?: number
  location?: string
  severity: ActivitySeverity
  details?: Record<string, any>
}

export interface DetectionRule {
  name: string
  type: UserActivityType
  timeWindowMinutes: number
  threshold: number
  severity: ActivitySeverity
}

@Injectable()
export class UserActivityService {
  private readonly logger = new Logger(UserActivityService.name)
  private readonly rules: DetectionRule[]
  private readonly activityRetentionDays: number
  private readonly maxLoginAttemptsBeforeLock: number
  private readonly loginLockoutMinutes: number
  private readonly impossibleTravelSpeedKph: number

  constructor(
    private readonly configService: ConfigService,
    @Inject(REDIS_SERVICE) private readonly redisService: RedisService,
    @Inject(EMAIL_SERVICE) private readonly emailService: EmailService,
    @Inject(GEOLOCATION_SERVICE) private readonly geolocationService: GeolocationService,
    private readonly i18nService: I18nService<I18nTranslations>,
    @Inject(USER_AGENT_SERVICE) private readonly userAgentService: UserAgentService,
    private readonly userRepository: UserRepository
  ) {
    // Cấu hình từ environment variables
    this.activityRetentionDays = this.configService.get<number>('USER_ACTIVITY_RETENTION_DAYS', 90)
    this.maxLoginAttemptsBeforeLock = this.configService.get<number>('MAX_LOGIN_ATTEMPTS_BEFORE_LOCK', 5)
    this.loginLockoutMinutes = this.configService.get<number>('LOGIN_LOCKOUT_MINUTES', 30)
    this.impossibleTravelSpeedKph = this.configService.get<number>('IMPOSSIBLE_TRAVEL_SPEED_KPH', 1000)

    // Khởi tạo các quy tắc phát hiện hoạt động đáng ngờ
    this.rules = [
      {
        name: 'Nhiều lần đăng nhập thất bại liên tiếp',
        type: UserActivityType.LOGIN_FAILURE,
        timeWindowMinutes: 10,
        threshold: 3,
        severity: ActivitySeverity.WARNING
      },
      {
        name: 'Di chuyển địa lý phi thực tế (impossible travel)',
        type: UserActivityType.LOGIN_SUCCESS,
        timeWindowMinutes: 240, // 4 giờ
        threshold: 2, // Cần ít nhất 2 lần đăng nhập để so sánh location
        severity: ActivitySeverity.CRITICAL
      },
      {
        name: 'Hành vi phục hồi mật khẩu đáng ngờ',
        type: UserActivityType.RECOVERY_ATTEMPT,
        timeWindowMinutes: 60,
        threshold: 3,
        severity: ActivitySeverity.WARNING
      },
      {
        name: 'Thay đổi mật khẩu nhiều lần trong ngày',
        type: UserActivityType.PASSWORD_CHANGED,
        timeWindowMinutes: 1440, // 24 giờ
        threshold: 3,
        severity: ActivitySeverity.WARNING
      },
      {
        name: 'Thay đổi email nhiều lần',
        type: UserActivityType.EMAIL_CHANGED,
        timeWindowMinutes: 1440, // 24h
        threshold: 2,
        severity: ActivitySeverity.WARNING
      }
    ]
  }

  async logActivity(activity: UserActivity): Promise<void> {
    // Lưu vào Redis danh sách hoạt động với timestamp
    const activityKey = RedisKeyManager.getUserActivityKey(activity.userId)
    const activityJson = JSON.stringify({
      ...activity,
      timestamp: activity.timestamp || Date.now()
    })

    // Thêm vào đầu danh sách (FIFO)
    await this.redisService.lpush(activityKey, activityJson)

    // Giữ danh sách trong giới hạn để tiết kiệm memory
    await this.redisService.ltrim(activityKey, 0, 99) // Giữ 100 hoạt động gần nhất

    // Thiết lập thời gian hết hạn cho data retention
    const ttl = await this.redisService.ttl(activityKey)
    if (ttl < 0) {
      await this.redisService.expire(activityKey, 60 * 60 * 24 * this.activityRetentionDays)
    }

    // Xử lý business logic theo loại hoạt động
    await this.processActivity(activity)

    // Kiểm tra vi phạm các quy tắc bảo mật
    await this.checkRuleViolations(activity)
  }

  private async processActivity(activity: UserActivity): Promise<void> {
    const userForPasswordChange = await this.userRepository.findByIdWithDetails(activity.userId)
    switch (activity.type) {
      case UserActivityType.LOGIN_FAILURE:
        await this.handleLoginFailure(activity)
        break
      case UserActivityType.LOGIN_SUCCESS:
        await this.handleLoginSuccess(activity)
        break
      case UserActivityType.PASSWORD_CHANGED:
        if (userForPasswordChange) {
          await this.handlePasswordChanged(activity, userForPasswordChange)
        }
        break
      case UserActivityType.EMAIL_CHANGED:
        await this.handleEmailChanged(activity)
        break
      case UserActivityType.TWO_FACTOR_ENABLED:
      case UserActivityType.TWO_FACTOR_DISABLED:
        await this.handleTwoFactorChange(activity)
        break
      default:
        // Không có xử lý đặc biệt
        break
    }
  }

  private async checkRuleViolations(activity: UserActivity): Promise<void> {
    const applicableRules = this.rules.filter((rule) => rule.type === activity.type)

    for (const rule of applicableRules) {
      const isViolated = await this.checkRule(activity.userId, rule)

      if (isViolated) {
        // Ghi lại vi phạm
        await this.logActivity({
          userId: activity.userId,
          type: UserActivityType.SUSPICIOUS_ACTIVITY,
          timestamp: Date.now(),
          ipAddress: activity.ipAddress,
          userAgent: activity.userAgent,
          deviceId: activity.deviceId,
          severity: rule.severity,
          details: {
            ruleName: rule.name,
            violationType: activity.type,
            threshold: rule.threshold
          }
        })

        const user = await this.userRepository.findByIdWithDetails(activity.userId)
        if (!user) {
          return
        }

        // Thông báo cho người dùng nếu nghiêm trọng
        if (rule.severity === ActivitySeverity.WARNING || rule.severity === ActivitySeverity.CRITICAL) {
          const extraDetails = await this.getExtraDetailsForRule(rule, activity.userId)
          await this.notifyUserAboutSuspiciousActivity(user, rule, activity, extraDetails)
        }

        // Nếu là đăng nhập thất bại và đạt ngưỡng khóa tài khoản
        if (activity.type === UserActivityType.LOGIN_FAILURE && rule.threshold >= this.maxLoginAttemptsBeforeLock) {
          await this.lockAccount(user, activity)
        }

        // Nếu là di chuyển phi thực tế, đặt cờ xác minh lại
        if (rule.name === 'Di chuyển phi thực tế') {
          await this.setReverifyFlagForUser(activity.userId)
        }
      }
    }
  }

  private async checkRule(userId: number, rule: DetectionRule): Promise<boolean> {
    // Xử lý riêng cho quy tắc di chuyển phi thực tế
    if (rule.name === 'Di chuyển phi thực tế') {
      return this.isImpossibleTravel(userId)
    }

    const activityKey = RedisKeyManager.getUserActivityKey(userId)
    const activities = await this.redisService.lrange(activityKey, 0, 99)

    if (!activities || activities.length === 0) return false

    // Lọc các hoạt động phù hợp với quy tắc và trong khung thời gian
    const now = Date.now()
    const timeWindowMs = rule.timeWindowMinutes * 60 * 1000
    const relevantActivities: UserActivity[] = []

    for (const activityJson of activities) {
      const activity = JSON.parse(activityJson)

      if (activity.type === rule.type) {
        const activityTime = activity.timestamp || 0

        if (now - activityTime <= timeWindowMs) {
          relevantActivities.push(activity)
        }
      }
    }

    // Kiểm tra số lượng hoạt động có vượt ngưỡng không
    return relevantActivities.length >= rule.threshold
  }

  private async isImpossibleTravel(userId: number): Promise<boolean> {
    const activities = await this.getUserActivityHistory(userId, 2, [UserActivityType.LOGIN_SUCCESS])
    if (activities.length < 2) {
      return false
    }

    const [currentActivity, previousActivity] = activities
    if (
      !currentActivity.ipAddress ||
      !previousActivity.ipAddress ||
      currentActivity.ipAddress === previousActivity.ipAddress
    ) {
      return false
    }

    const [currentLocation, previousLocation] = await Promise.all([
      this.geolocationService.getLocationFromIP(currentActivity.ipAddress || ''),
      this.geolocationService.getLocationFromIP(previousActivity.ipAddress || '')
    ])

    if (!this.areCoordinatesValid(currentLocation) || !this.areCoordinatesValid(previousLocation)) {
      return false
    }

    const distanceKm = calculateDistance(
      { lat: currentLocation.lat, lon: currentLocation.lon },
      { lat: previousLocation.lat, lon: previousLocation.lon }
    )

    const timeDiffHours = (currentActivity.timestamp - previousActivity.timestamp) / (1000 * 60 * 60)
    if (timeDiffHours <= 0) {
      return distanceKm > 10 // True if moved far in no time
    }

    const speedKph = distanceKm / timeDiffHours
    return speedKph > this.impossibleTravelSpeedKph
  }

  private async handleLoginFailure(activity: UserActivity): Promise<void> {
    const failureKey = RedisKeyManager.getLoginFailuresKey(activity.userId)
    await this.redisService.lpush(failureKey, JSON.stringify({ timestamp: activity.timestamp }))
    await this.redisService.ltrim(failureKey, 0, this.maxLoginAttemptsBeforeLock * 2)
    await this.redisService.expire(failureKey, this.loginLockoutMinutes * 60)
  }

  private async handleLoginSuccess(activity: UserActivity): Promise<void> {
    const failureKey = RedisKeyManager.getLoginFailuresKey(activity.userId)
    await this.redisService.del(failureKey)

    const lastLoginKey = RedisKeyManager.getLastLoginTimestampKey(activity.userId)
    await this.redisService.set(lastLoginKey, activity.timestamp.toString())
  }

  private async handlePasswordChanged(activity: UserActivity, user: UserWithProfileAndRole): Promise<void> {
    if (!user) return

    const uaInfo = this.userAgentService.parse(activity.userAgent)

    await this.emailService.sendPasswordChangedEmail(user.email, {
      userName: user.userProfile?.username ?? user.email,
      details: [
        {
          label: 'email.Email.common.details.ipAddress',
          value: activity.ipAddress ?? 'N/A'
        },
        {
          label: 'email.Email.common.details.device',
          value: `${uaInfo.browser} on ${uaInfo.os}`
        }
      ]
    })
  }

  private async handleEmailChanged(activity: UserActivity): Promise<void> {
    const emailChangeKey = RedisKeyManager.getEmailChangesKey(activity.userId)
    await this.redisService.lpush(
      emailChangeKey,
      JSON.stringify({ newEmail: activity.details?.newEmail, timestamp: activity.timestamp })
    )
    await this.redisService.ltrim(emailChangeKey, 0, 9)
    await this.redisService.expire(emailChangeKey, 60 * 60 * 24 * 90) // 90 ngày
  }

  private async handleTwoFactorChange(activity: UserActivity): Promise<void> {
    const twoFactorChangeKey = RedisKeyManager.getTwoFactorChangesKey(activity.userId)
    await this.redisService.lpush(
      twoFactorChangeKey,
      JSON.stringify({
        type: activity.type,
        timestamp: activity.timestamp
      })
    )
    await this.redisService.ltrim(twoFactorChangeKey, 0, 9)
    await this.redisService.expire(twoFactorChangeKey, 60 * 60 * 24 * 365) // 1 năm
  }

  private async lockAccount(user: UserWithProfileAndRole, activity: UserActivity): Promise<void> {
    const lockKey = RedisKeyManager.getAccountLockKey(user.id)
    await this.redisService.set(lockKey, 'locked', 'EX', this.loginLockoutMinutes * 60)

    await this.userRepository.update(user.id, {})

    await this.emailService.sendAccountLockedEmail(user.email, {
      userName: user.userProfile?.username ?? user.email,
      lockoutMinutes: this.loginLockoutMinutes,
      details: [
        {
          label: 'email.Email.common.details.ipAddress',
          value: activity.ipAddress ?? 'N/A'
        },
        {
          label: 'email.Email.common.details.location',
          value: activity.location ?? 'N/A'
        }
      ]
    })

    // Ghi lại hoạt động khóa tài khoản
    await this.logActivity({
      userId: user.id,
      type: UserActivityType.ACCOUNT_LOCKED,
      timestamp: Date.now(),
      ipAddress: activity.ipAddress,
      userAgent: activity.userAgent,
      deviceId: activity.deviceId,
      severity: ActivitySeverity.CRITICAL,
      details: { lockedBy: 'system' }
    })
  }

  async isAccountLocked(userId: number): Promise<boolean> {
    const lockKey = RedisKeyManager.getAccountLockKey(userId)
    return (await this.redisService.exists(lockKey)) > 0
  }

  async unlockAccount(userId: number, adminId?: number): Promise<void> {
    const lockKey = RedisKeyManager.getAccountLockKey(userId)
    const result = await this.redisService.del(lockKey)

    if (result > 0) {
      // Ghi lại hoạt động mở khóa
      await this.logActivity({
        userId,
        type: UserActivityType.ACCOUNT_UNLOCKED,
        timestamp: Date.now(),
        severity: ActivitySeverity.INFO,
        details: {
          unlockedBy: adminId ? `Admin (ID: ${adminId})` : 'System (automatic)',
          previousLockData: null
        }
      })
    }
  }

  private async setReverifyFlagForUser(userId: number): Promise<void> {
    const key = RedisKeyManager.getUserReverifyNextLoginKey(userId)
    const ttl = 24 * 60 * 60 // 24 giờ
    await this.redisService.set(key, '1', 'EX', ttl)
  }

  private async notifyUserAboutSuspiciousActivity(
    user: UserWithProfileAndRole,
    rule: DetectionRule,
    activity: UserActivity,
    extraDetails?: Record<string, any>
  ): Promise<void> {
    const notificationKey = RedisKeyManager.getSuspiciousActivityNotificationKey(user.id, rule.name)
    const alreadyNotified = await this.redisService.get(notificationKey)

    if (alreadyNotified) {
      return
    }

    const activityName = this.getUserFriendlyActivityName(activity.type)
    const suspiciousDetails =
      rule.name === 'Di chuyển phi thực tế'
        ? `Phát hiện đăng nhập từ hai vị trí cách xa nhau trong một khoảng thời gian ngắn (tốc độ ước tính: ${
            extraDetails?.speed ?? 'N/A'
          } km/h).`
        : `Phát hiện ${rule.threshold} lần ${activityName.toLowerCase()} trong ${rule.timeWindowMinutes} phút.`

    const uaInfo = this.userAgentService.parse(activity.userAgent)
    const lang = I18nContext.current()?.lang === 'en' ? 'en' : 'vi'
    const localeForDate = lang === 'vi' ? 'vi-VN' : 'en-US'
    const locationResult = await this.geolocationService.getLocationFromIP(activity.ipAddress ?? '')

    await this.emailService.sendSuspiciousActivityEmail(user.email, {
      userName: user.userProfile?.username ?? user.email,
      details: [
        {
          label: 'email.Email.securityAlert.SUSPICIOUS_ACTIVITY.details.activityDetected',
          value: activityName
        },
        {
          label: 'email.Email.securityAlert.SUSPICIOUS_ACTIVITY.details.reason',
          value: suspiciousDetails
        },
        {
          label: 'email.Email.common.details.time',
          value: new Date(activity.timestamp).toLocaleString(localeForDate, {
            timeZone: locationResult.timezone || 'Asia/Ho_Chi_Minh',
            dateStyle: 'full',
            timeStyle: 'long'
          })
        },
        {
          label: 'email.Email.common.details.ipAddress',
          value: activity.ipAddress ?? 'N/A'
        },
        {
          label: 'email.Email.common.details.location',
          value: activity.location ?? extraDetails?.currentLocation ?? 'N/A'
        },
        {
          label: 'email.Email.common.details.browser',
          value: [uaInfo.browser, uaInfo.browserVersion].filter(Boolean).join(' ') || 'N/A'
        },
        {
          label: 'email.Email.common.details.os',
          value: [uaInfo.os, uaInfo.osVersion].filter(Boolean).join(' ') || 'N/A'
        }
      ],
      lang
    })

    // Đánh dấu đã thông báo để tránh spam, sử dụng timeWindow của rule hoặc một giá trị mặc định
    const notificationTtl = rule.timeWindowMinutes > 0 ? rule.timeWindowMinutes * 60 : 60 * 60 // 1 giờ
    await this.redisService.set(notificationKey, 'sent', 'EX', notificationTtl)
  }

  private getUserFriendlyActivityName(activityType: UserActivityType): string {
    switch (activityType) {
      case UserActivityType.LOGIN_ATTEMPT:
        return 'Đăng nhập'
      case UserActivityType.LOGIN_SUCCESS:
        return 'Đăng nhập thành công'
      case UserActivityType.LOGIN_FAILURE:
        return 'Đăng nhập thất bại'
      case UserActivityType.PASSWORD_CHANGED:
        return 'Thay đổi mật khẩu'
      case UserActivityType.EMAIL_CHANGED:
        return 'Thay đổi email'
      case UserActivityType.PROFILE_UPDATED:
        return 'Cập nhật hồ sơ'
      case UserActivityType.TWO_FACTOR_ENABLED:
        return 'Bật xác thực hai yếu tố'
      case UserActivityType.TWO_FACTOR_DISABLED:
        return 'Tắt xác thực hai yếu tố'
      case UserActivityType.RECOVERY_ATTEMPT:
        return 'Khôi phục tài khoản'
      case UserActivityType.SUSPICIOUS_ACTIVITY:
        return 'Hoạt động đáng ngờ'
      case UserActivityType.ACCOUNT_LOCKED:
        return 'Tài khoản bị khóa'
      case UserActivityType.ACCOUNT_UNLOCKED:
        return 'Tài khoản được mở khóa'
      default:
        return 'Hoạt động không xác định'
    }
  }

  async getUserActivityHistory(
    userId: number,
    limit: number = 20,
    activityTypes?: UserActivityType[]
  ): Promise<UserActivity[]> {
    try {
      const activityKey = RedisKeyManager.getUserActivityKey(userId)
      const activitiesJson = await this.redisService.lrange(activityKey, 0, limit - 1)

      if (!activitiesJson) {
        return []
      }

      const result: UserActivity[] = []

      for (const activityJson of activitiesJson) {
        const activity = JSON.parse(activityJson) as UserActivity

        // Lọc theo loại hoạt động nếu có
        if (activityTypes && activityTypes.length > 0) {
          if (!activityTypes.includes(activity.type)) {
            continue
          }
        }

        result.push(activity)
      }

      return result
    } catch {
      return []
    }
  }

  private areCoordinatesValid(location: GeoLocationResult): location is GeoLocationResult & Coordinates {
    return typeof location.lat === 'number' && typeof location.lon === 'number'
  }

  private async getExtraDetailsForRule(rule: DetectionRule, userId: number): Promise<Record<string, any> | undefined> {
    if (rule.name === 'Di chuyển phi thực tế') {
      const activities = await this.getUserActivityHistory(userId, 2, [UserActivityType.LOGIN_SUCCESS])
      if (activities.length < 2) return undefined

      const [currentActivity, previousActivity] = activities
      const [currentLocation, previousLocation] = await Promise.all([
        this.geolocationService.getLocationFromIP(currentActivity.ipAddress ?? ''),
        this.geolocationService.getLocationFromIP(previousActivity.ipAddress ?? '')
      ])

      if (!this.areCoordinatesValid(currentLocation) || !this.areCoordinatesValid(previousLocation)) {
        return undefined
      }

      const distanceKm = calculateDistance(
        { lat: currentLocation.lat, lon: currentLocation.lon },
        { lat: previousLocation.lat, lon: previousLocation.lon }
      )
      const timeDiffHours = (currentActivity.timestamp - previousActivity.timestamp) / (1000 * 60 * 60)
      const speedKph = timeDiffHours > 0 ? distanceKm / timeDiffHours : 0

      return {
        previousLocation: previousLocation.display,
        currentLocation: currentLocation.display,
        speed: speedKph.toFixed(0)
      }
    }
    return undefined
  }
}
