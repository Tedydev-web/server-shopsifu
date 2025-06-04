import { Injectable, Logger, Inject } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { RedisService } from 'src/shared/providers/redis/redis.service'
import { EmailService, SecurityAlertType } from 'src/shared/services/email.service'
import { EMAIL_SERVICE, REDIS_SERVICE } from 'src/shared/constants/injection.tokens'
import { UserAuthRepository } from 'src/shared/repositories/auth'
import { RedisKeyManager } from 'src/shared/utils/redis-keys.utils'

/**
 * Các loại hoạt động người dùng
 */
export enum UserActivityType {
  LOGIN_ATTEMPT = 'LOGIN_ATTEMPT',
  LOGIN_SUCCESS = 'LOGIN_SUCCESS',
  LOGIN_FAILURE = 'LOGIN_FAILURE',
  PASSWORD_CHANGED = 'PASSWORD_CHANGED',
  EMAIL_CHANGED = 'EMAIL_CHANGED',
  PROFILE_UPDATED = 'PROFILE_UPDATED',
  TWO_FACTOR_ENABLED = 'TWO_FACTOR_ENABLED',
  TWO_FACTOR_DISABLED = 'TWO_FACTOR_DISABLED',
  RECOVERY_ATTEMPT = 'RECOVERY_ATTEMPT',
  SUSPICIOUS_ACTIVITY = 'SUSPICIOUS_ACTIVITY',
  ACCOUNT_LOCKED = 'ACCOUNT_LOCKED',
  ACCOUNT_UNLOCKED = 'ACCOUNT_UNLOCKED'
}

/**
 * Các mức độ nghiêm trọng
 */
export enum ActivitySeverity {
  INFO = 'INFO',
  WARNING = 'WARNING',
  CRITICAL = 'CRITICAL'
}

/**
 * Thông tin hoạt động người dùng
 */
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

/**
 * Quy tắc phát hiện hoạt động đáng ngờ
 */
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

  constructor(
    private readonly configService: ConfigService,
    private readonly redisService: RedisService,
    @Inject(EMAIL_SERVICE) private readonly emailService: EmailService,
    private readonly userAuthRepository: UserAuthRepository
  ) {
    // Cấu hình quy tắc phát hiện
    this.activityRetentionDays = this.configService.get<number>('USER_ACTIVITY_RETENTION_DAYS', 90)
    this.maxLoginAttemptsBeforeLock = this.configService.get<number>('MAX_LOGIN_ATTEMPTS_BEFORE_LOCK', 5)
    this.loginLockoutMinutes = this.configService.get<number>('LOGIN_LOCKOUT_MINUTES', 30)

    // Khởi tạo các quy tắc phát hiện
    this.rules = [
      {
        name: 'Nhiều lần đăng nhập thất bại',
        type: UserActivityType.LOGIN_FAILURE,
        timeWindowMinutes: 10,
        threshold: 3,
        severity: ActivitySeverity.WARNING
      },
      {
        name: 'Hành vi phục hồi mật khẩu đáng ngờ',
        type: UserActivityType.RECOVERY_ATTEMPT,
        timeWindowMinutes: 60,
        threshold: 3,
        severity: ActivitySeverity.WARNING
      },
      {
        name: 'Thay đổi mật khẩu nhiều lần',
        type: UserActivityType.PASSWORD_CHANGED,
        timeWindowMinutes: 1440, // 24h
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

  /**
   * Ghi lại hoạt động của người dùng
   */
  async logActivity(activity: UserActivity): Promise<void> {
    this.logger.debug(`[logActivity] Recording activity: ${activity.type} for user ${activity.userId}`)

    try {
      // Lưu vào Redis danh sách hoạt động
      const activityKey = RedisKeyManager.userActivityKey(activity.userId)
      const activityJson = JSON.stringify({
        ...activity,
        timestamp: activity.timestamp || Date.now()
      })

      // Thêm vào đầu danh sách
      await this.redisService.lpush(activityKey, activityJson)

      // Giữ danh sách trong giới hạn
      await this.redisService.ltrim(activityKey, 0, 99) // Giữ 100 hoạt động gần nhất

      // Thiết lập thời gian hết hạn nếu chưa có
      const ttl = await this.redisService.ttl(activityKey)
      if (ttl < 0) {
        await this.redisService.expire(activityKey, 60 * 60 * 24 * this.activityRetentionDays)
      }

      // Xử lý theo loại hoạt động
      await this.processActivity(activity)

      // Kiểm tra vi phạm các quy tắc
      await this.checkRuleViolations(activity)
    } catch (error) {
      this.logger.error(`[logActivity] Error: ${error.message}`, error.stack)
    }
  }

  /**
   * Xử lý hoạt động dựa vào loại
   */
  private async processActivity(activity: UserActivity): Promise<void> {
    try {
      switch (activity.type) {
        case UserActivityType.LOGIN_FAILURE:
          await this.handleLoginFailure(activity)
          break

        case UserActivityType.LOGIN_SUCCESS:
          await this.handleLoginSuccess(activity)
          break

        case UserActivityType.PASSWORD_CHANGED:
          await this.handlePasswordChanged(activity)
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
    } catch (error) {
      this.logger.error(`[processActivity] Error processing activity ${activity.type}: ${error.message}`)
    }
  }

  /**
   * Kiểm tra vi phạm quy tắc
   */
  private async checkRuleViolations(activity: UserActivity): Promise<void> {
    // Kiểm tra từng quy tắc phù hợp với loại hoạt động
    const applicableRules = this.rules.filter((rule) => rule.type === activity.type)

    for (const rule of applicableRules) {
      const isViolated = await this.checkRule(activity.userId, rule)

      if (isViolated) {
        this.logger.warn(`[checkRuleViolations] Rule "${rule.name}" violated by user ${activity.userId}`)

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

        // Thông báo cho người dùng nếu nghiêm trọng
        if (rule.severity === ActivitySeverity.WARNING || rule.severity === ActivitySeverity.CRITICAL) {
          await this.notifyUserAboutSuspiciousActivity(activity.userId, rule, activity)
        }

        // Nếu là đăng nhập thất bại và đạt ngưỡng khóa tài khoản
        if (activity.type === UserActivityType.LOGIN_FAILURE && rule.threshold >= this.maxLoginAttemptsBeforeLock) {
          await this.lockAccount(activity.userId, activity)
        }
      }
    }
  }

  /**
   * Kiểm tra một quy tắc cụ thể
   */
  private async checkRule(userId: number, rule: DetectionRule): Promise<boolean> {
    const activityKey = RedisKeyManager.userActivityKey(userId)
    const activities = await this.redisService.lrange(activityKey, 0, 99)

    if (!activities || activities.length === 0) return false

    // Lọc các hoạt động phù hợp với quy tắc và trong khung thời gian
    const now = Date.now()
    const timeWindowMs = rule.timeWindowMinutes * 60 * 1000
    const relevantActivities: UserActivity[] = []

    for (const activityJson of activities) {
      try {
        const activity = JSON.parse(activityJson)

        if (activity.type === rule.type) {
          const activityTime = activity.timestamp || 0

          if (now - activityTime <= timeWindowMs) {
            relevantActivities.push(activity)
          }
        }
      } catch (error) {
        this.logger.error(`[checkRule] Error parsing activity: ${error.message}`)
      }
    }

    // Kiểm tra số lượng hoạt động có vượt ngưỡng không
    return relevantActivities.length >= rule.threshold
  }

  /**
   * Xử lý đăng nhập thất bại
   */
  private async handleLoginFailure(activity: UserActivity): Promise<void> {
    // Tăng số lần đăng nhập thất bại
    const failureKey = RedisKeyManager.loginFailuresKey(activity.userId)
    const currentFailures = await this.redisService.get(failureKey)
    const failureCount = currentFailures ? parseInt(currentFailures, 10) + 1 : 1

    // Lưu vào Redis với thời gian hết hạn
    await this.redisService.set(failureKey, failureCount.toString(), 'EX', 60 * 30) // Hết hạn sau 30 phút

    this.logger.debug(`[handleLoginFailure] User ${activity.userId} has ${failureCount} failed login attempts`)

    // Nếu đạt ngưỡng khóa tài khoản
    if (failureCount >= this.maxLoginAttemptsBeforeLock) {
      this.logger.warn(`[handleLoginFailure] User ${activity.userId} reached max login attempts, locking account`)
    }
  }

  /**
   * Xử lý đăng nhập thành công
   */
  private async handleLoginSuccess(activity: UserActivity): Promise<void> {
    // Xóa số lần đăng nhập thất bại
    const failureKey = RedisKeyManager.loginFailuresKey(activity.userId)
    await this.redisService.del(failureKey)

    // Cập nhật thời gian đăng nhập cuối
    const lastLoginKey = RedisKeyManager.lastLoginKey(activity.userId)
    await this.redisService.set(
      lastLoginKey,
      JSON.stringify({
        timestamp: activity.timestamp || Date.now(),
        ipAddress: activity.ipAddress,
        userAgent: activity.userAgent,
        location: activity.location
      })
    )
  }

  /**
   * Xử lý thay đổi mật khẩu
   */
  private async handlePasswordChanged(activity: UserActivity): Promise<void> {
    try {
      const user = await this.userAuthRepository.findById(activity.userId)
      if (!user) return

      // Gửi thông báo cho người dùng
      await this.emailService.sendSecurityAlertEmail(SecurityAlertType.PASSWORD_CHANGED, user.email, {
        userName: user.userProfile?.firstName || user.email.split('@')[0],
        timestamp: new Date(activity.timestamp || Date.now()).toISOString(),
        ipAddress: activity.ipAddress || 'Unknown',
        location: activity.location || 'Unknown location',
        deviceInfo: activity.userAgent ? this.extractDeviceInfo(activity.userAgent) : 'Unknown device'
      })

      this.logger.debug(`[handlePasswordChanged] Sent password change notification to user ${activity.userId}`)

      // Lưu lịch sử thay đổi mật khẩu
      const passwordChangeKey = RedisKeyManager.passwordChangesKey(activity.userId)
      await this.redisService.lpush(
        passwordChangeKey,
        JSON.stringify({
          timestamp: activity.timestamp || Date.now(),
          ipAddress: activity.ipAddress,
          userAgent: activity.userAgent
        })
      )
      await this.redisService.ltrim(passwordChangeKey, 0, 9) // Giữ 10 lần thay đổi gần nhất
    } catch (error) {
      this.logger.error(`[handlePasswordChanged] Error: ${error.message}`)
    }
  }

  /**
   * Xử lý thay đổi email
   */
  private async handleEmailChanged(activity: UserActivity): Promise<void> {
    try {
      const user = await this.userAuthRepository.findById(activity.userId)
      if (!user) return

      // Thông tin email cũ và mới
      const oldEmail = activity.details?.oldEmail
      const newEmail = activity.details?.newEmail || user.email

      // Gửi thông báo cho cả email cũ và mới
      if (oldEmail) {
        await this.emailService.sendSecurityAlertEmail(SecurityAlertType.EMAIL_CHANGED, oldEmail, {
          userName: user.userProfile?.firstName || oldEmail.split('@')[0],
          timestamp: new Date(activity.timestamp || Date.now()).toISOString(),
          ipAddress: activity.ipAddress || 'Unknown',
          location: activity.location || 'Unknown location',
          deviceInfo: activity.userAgent ? this.extractDeviceInfo(activity.userAgent) : 'Unknown device',
          oldEmail,
          newEmail
        })
      }

      await this.emailService.sendSecurityAlertEmail(SecurityAlertType.EMAIL_CHANGED, newEmail, {
        userName: user.userProfile?.firstName || newEmail.split('@')[0],
        timestamp: new Date(activity.timestamp || Date.now()).toISOString(),
        ipAddress: activity.ipAddress || 'Unknown',
        location: activity.location || 'Unknown location',
        deviceInfo: activity.userAgent ? this.extractDeviceInfo(activity.userAgent) : 'Unknown device',
        oldEmail,
        newEmail
      })

      this.logger.debug(`[handleEmailChanged] Sent email change notifications for user ${activity.userId}`)
    } catch (error) {
      this.logger.error(`[handleEmailChanged] Error: ${error.message}`)
    }
  }

  /**
   * Xử lý thay đổi xác thực hai yếu tố
   */
  private async handleTwoFactorChange(activity: UserActivity): Promise<void> {
    try {
      const user = await this.userAuthRepository.findById(activity.userId)
      if (!user) return

      const isEnabled = activity.type === UserActivityType.TWO_FACTOR_ENABLED
      const alertType = isEnabled ? SecurityAlertType.TWO_FACTOR_ENABLED : SecurityAlertType.TWO_FACTOR_DISABLED

      await this.emailService.sendSecurityAlertEmail(alertType, user.email, {
        userName: user.userProfile?.firstName || user.email.split('@')[0],
        timestamp: new Date(activity.timestamp || Date.now()).toISOString(),
        ipAddress: activity.ipAddress || 'Unknown',
        location: activity.location || 'Unknown location',
        deviceInfo: activity.userAgent ? this.extractDeviceInfo(activity.userAgent) : 'Unknown device'
      })

      this.logger.debug(
        `[handleTwoFactorChange] Sent 2FA ${isEnabled ? 'enabled' : 'disabled'} notification to user ${activity.userId}`
      )
    } catch (error) {
      this.logger.error(`[handleTwoFactorChange] Error: ${error.message}`)
    }
  }

  /**
   * Khóa tài khoản người dùng
   */
  private async lockAccount(userId: number, activity: UserActivity): Promise<void> {
    try {
      // Đặt khóa tài khoản trong Redis
      const lockKey = RedisKeyManager.accountLockKey(userId)
      await this.redisService.set(
        lockKey,
        JSON.stringify({
          lockedAt: Date.now(),
          reason: 'Too many failed login attempts',
          ipAddress: activity.ipAddress,
          userAgent: activity.userAgent
        }),
        'EX',
        60 * this.loginLockoutMinutes
      )

      // Ghi lại hoạt động khóa tài khoản
      await this.logActivity({
        userId,
        type: UserActivityType.ACCOUNT_LOCKED,
        timestamp: Date.now(),
        ipAddress: activity.ipAddress,
        userAgent: activity.userAgent,
        severity: ActivitySeverity.CRITICAL,
        details: {
          reason: 'Too many failed login attempts',
          lockoutMinutes: this.loginLockoutMinutes
        }
      })

      // Thông báo cho người dùng
      const user = await this.userAuthRepository.findById(userId)
      if (user) {
        await this.emailService.sendSecurityAlertEmail(SecurityAlertType.ACCOUNT_LOCKED, user.email, {
          userName: user.userProfile?.firstName || user.email.split('@')[0],
          timestamp: new Date().toISOString(),
          ipAddress: activity.ipAddress || 'Unknown',
          location: activity.location || 'Unknown location',
          deviceInfo: activity.userAgent ? this.extractDeviceInfo(activity.userAgent) : 'Unknown device',
          lockoutMinutes: this.loginLockoutMinutes,
          reason: 'Too many failed login attempts'
        })
      }

      this.logger.warn(`[lockAccount] Account locked for user ${userId} due to failed login attempts`)
    } catch (error) {
      this.logger.error(`[lockAccount] Error: ${error.message}`)
    }
  }

  /**
   * Kiểm tra xem tài khoản có bị khóa không
   */
  async isAccountLocked(userId: number): Promise<boolean> {
    const lockKey = RedisKeyManager.accountLockKey(userId)
    return (await this.redisService.exists(lockKey)) > 0
  }

  /**
   * Mở khóa tài khoản người dùng
   */
  async unlockAccount(userId: number, adminId?: number): Promise<void> {
    try {
      const lockKey = RedisKeyManager.accountLockKey(userId)
      const lockData = await this.redisService.get(lockKey)

      // Xóa khóa tài khoản
      await this.redisService.del(lockKey)

      // Ghi lại hoạt động mở khóa
      await this.logActivity({
        userId,
        type: UserActivityType.ACCOUNT_UNLOCKED,
        timestamp: Date.now(),
        severity: ActivitySeverity.INFO,
        details: {
          unlockedBy: adminId ? `Admin (ID: ${adminId})` : 'System (automatic)',
          previousLockData: lockData ? JSON.parse(lockData) : null
        }
      })

      this.logger.log(`[unlockAccount] Account unlocked for user ${userId}`)
    } catch (error) {
      this.logger.error(`[unlockAccount] Error: ${error.message}`)
    }
  }

  /**
   * Thông báo cho người dùng về hoạt động đáng ngờ
   */
  private async notifyUserAboutSuspiciousActivity(
    userId: number,
    rule: DetectionRule,
    activity: UserActivity
  ): Promise<void> {
    try {
      const user = await this.userAuthRepository.findById(userId)
      if (!user) return

      // Kiểm tra đã thông báo gần đây chưa để tránh spam
      const notificationKey = RedisKeyManager.suspiciousActivityNotificationKey(userId, rule.type)
      const lastNotification = await this.redisService.get(notificationKey)

      if (lastNotification) {
        // Đã thông báo trong vòng 1 giờ, không gửi lại
        return
      }

      // Gửi email thông báo
      await this.emailService.sendSecurityAlertEmail(SecurityAlertType.SUSPICIOUS_ACTIVITY, user.email, {
        userName: user.userProfile?.firstName || user.email.split('@')[0],
        timestamp: new Date(activity.timestamp || Date.now()).toISOString(),
        ipAddress: activity.ipAddress || 'Unknown',
        location: activity.location || 'Unknown location',
        deviceInfo: activity.userAgent ? this.extractDeviceInfo(activity.userAgent) : 'Unknown device',
        activityType: this.getUserFriendlyActivityName(activity.type),
        suspiciousDetails: rule.name,
        severity: rule.severity
      })

      // Đánh dấu đã thông báo (1 giờ)
      await this.redisService.set(notificationKey, Date.now().toString(), 'EX', 60 * 60)

      this.logger.debug(
        `[notifyUserAboutSuspiciousActivity] Sent suspicious activity notification to user ${userId} for rule "${rule.name}"`
      )
    } catch (error) {
      this.logger.error(`[notifyUserAboutSuspiciousActivity] Error: ${error.message}`)
    }
  }

  /**
   * Chuyển đổi loại hoạt động thành tên thân thiện với người dùng
   */
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

  /**
   * Trích xuất thông tin thiết bị từ user agent
   */
  private extractDeviceInfo(userAgent: string): string {
    if (!userAgent) return 'Unknown device'

    let deviceInfo = 'Unknown device'

    // Trích xuất thông tin thiết bị
    if (/iPhone/i.test(userAgent)) {
      deviceInfo = 'iPhone'
    } else if (/iPad/i.test(userAgent)) {
      deviceInfo = 'iPad'
    } else if (/Android/i.test(userAgent)) {
      deviceInfo = 'Android device'
    } else if (/Windows/i.test(userAgent)) {
      deviceInfo = 'Windows device'
    } else if (/Mac/i.test(userAgent)) {
      deviceInfo = 'Mac'
    } else if (/Linux/i.test(userAgent)) {
      deviceInfo = 'Linux device'
    }

    // Trích xuất thông tin trình duyệt
    let browserInfo = ''
    if (/Chrome/i.test(userAgent) && !/Chromium|OPR|Edge/i.test(userAgent)) {
      browserInfo = 'Chrome'
    } else if (/Firefox/i.test(userAgent)) {
      browserInfo = 'Firefox'
    } else if (/Safari/i.test(userAgent) && !/Chrome|Chromium|Edge/i.test(userAgent)) {
      browserInfo = 'Safari'
    } else if (/Edge/i.test(userAgent)) {
      browserInfo = 'Edge'
    } else if (/Opera|OPR/i.test(userAgent)) {
      browserInfo = 'Opera'
    } else if (/MSIE|Trident/i.test(userAgent)) {
      browserInfo = 'Internet Explorer'
    }

    return browserInfo ? `${deviceInfo} (${browserInfo})` : deviceInfo
  }

  /**
   * Lấy lịch sử hoạt động của người dùng
   */
  async getUserActivityHistory(
    userId: number,
    limit: number = 20,
    activityTypes?: UserActivityType[]
  ): Promise<UserActivity[]> {
    try {
      const activityKey = RedisKeyManager.userActivityKey(userId)
      const activities = await this.redisService.lrange(activityKey, 0, limit - 1)

      if (!activities || activities.length === 0) {
        return []
      }

      const result: UserActivity[] = []

      for (const activityJson of activities) {
        try {
          const activity = JSON.parse(activityJson) as UserActivity

          // Lọc theo loại hoạt động nếu có
          if (activityTypes && activityTypes.length > 0) {
            if (!activityTypes.includes(activity.type)) {
              continue
            }
          }

          result.push(activity)
        } catch (error) {
          this.logger.error(`[getUserActivityHistory] Error parsing activity: ${error.message}`)
        }
      }

      return result
    } catch (error) {
      this.logger.error(`[getUserActivityHistory] Error: ${error.message}`)
      return []
    }
  }
}
