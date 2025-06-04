import { Injectable, Logger } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { RedisService } from 'src/shared/providers/redis/redis.service'
import { EmailService, SecurityAlertType } from 'src/shared/services/email.service'
import { UserAuthRepository } from '../repositories/user-auth.repository'

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
    private readonly emailService: EmailService,
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
      const activityKey = `user:${activity.userId}:activities`
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
    const activityKey = `user:${userId}:activities`
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

    // Kiểm tra số lượng
    return relevantActivities.length >= rule.threshold
  }

  /**
   * Xử lý đăng nhập thất bại
   */
  private async handleLoginFailure(activity: UserActivity): Promise<void> {
    const { userId, ipAddress } = activity

    // Tăng bộ đếm đăng nhập thất bại
    const failureKey = `user:${userId}:login_failures`
    const failureCount = await this.redisService.incr(failureKey)

    // Thiết lập TTL nếu là lượt thất bại đầu tiên
    if (failureCount === 1) {
      await this.redisService.expire(failureKey, 60 * 30) // Hết hạn sau 30 phút
    }

    this.logger.debug(`[handleLoginFailure] User ${userId} has ${failureCount} login failures`)

    // Kiểm tra có cần khóa tài khoản không
    if (failureCount >= this.maxLoginAttemptsBeforeLock) {
      await this.lockAccount(userId, activity)
    }
  }

  /**
   * Xử lý đăng nhập thành công
   */
  private async handleLoginSuccess(activity: UserActivity): Promise<void> {
    const { userId } = activity

    // Xóa bộ đếm đăng nhập thất bại
    const failureKey = `user:${userId}:login_failures`
    await this.redisService.del(failureKey)

    // Xóa trạng thái khóa tài khoản nếu có
    const lockKey = `user:${userId}:account_locked`
    await this.redisService.del(lockKey)
  }

  /**
   * Xử lý thay đổi mật khẩu
   */
  private async handlePasswordChanged(activity: UserActivity): Promise<void> {
    // Đo thời gian giữa các lần thay đổi mật khẩu
    const { userId } = activity
    const key = `user:${userId}:last_password_change`

    try {
      const lastChange = await this.redisService.get(key)

      if (lastChange) {
        const lastChangeTime = parseInt(lastChange, 10)
        const timeSinceLastChange = Date.now() - lastChangeTime
        const hoursSinceLastChange = timeSinceLastChange / (1000 * 60 * 60)

        // Nếu thay đổi quá nhanh (dưới 24h), có thể đáng ngờ
        if (hoursSinceLastChange < 24) {
          this.logger.warn(
            `[handlePasswordChanged] User ${userId} changed password again after only ${hoursSinceLastChange.toFixed(2)} hours`
          )
        }
      }

      // Cập nhật thời gian thay đổi mật khẩu
      await this.redisService.set(key, Date.now().toString())
    } catch (error) {
      this.logger.error(`[handlePasswordChanged] Error: ${error.message}`)
    }
  }

  /**
   * Xử lý thay đổi email
   */
  private async handleEmailChanged(activity: UserActivity): Promise<void> {
    // Tương tự như thay đổi mật khẩu
    const { userId } = activity
    const key = `user:${userId}:last_email_change`

    try {
      const lastChange = await this.redisService.get(key)

      if (lastChange) {
        const lastChangeTime = parseInt(lastChange, 10)
        const timeSinceLastChange = Date.now() - lastChangeTime
        const daysSinceLastChange = timeSinceLastChange / (1000 * 60 * 60 * 24)

        // Nếu thay đổi quá nhanh (dưới 7 ngày), có thể đáng ngờ
        if (daysSinceLastChange < 7) {
          this.logger.warn(
            `[handleEmailChanged] User ${userId} changed email again after only ${daysSinceLastChange.toFixed(2)} days`
          )
        }
      }

      // Cập nhật thời gian thay đổi email
      await this.redisService.set(key, Date.now().toString())
    } catch (error) {
      this.logger.error(`[handleEmailChanged] Error: ${error.message}`)
    }
  }

  /**
   * Xử lý thay đổi 2FA
   */
  private async handleTwoFactorChange(activity: UserActivity): Promise<void> {
    // Gửi thông báo cho người dùng về thay đổi bảo mật quan trọng
    try {
      const user = await this.userAuthRepository.findById(activity.userId)
      if (!user) return

      const alertType =
        activity.type === UserActivityType.TWO_FACTOR_ENABLED
          ? SecurityAlertType.TWO_FACTOR_ENABLED
          : SecurityAlertType.TWO_FACTOR_DISABLED

      await this.emailService.sendSecurityAlertEmail(alertType, user.email, {
        userName: user.userProfile?.firstName || user.email.split('@')[0],
        ipAddress: activity.ipAddress,
        time: new Date().toISOString(),
        location: activity.location || 'Unknown location'
      })
    } catch (error) {
      this.logger.error(`[handleTwoFactorChange] Error sending notification: ${error.message}`)
    }
  }

  /**
   * Khóa tài khoản người dùng
   */
  private async lockAccount(userId: number, activity: UserActivity): Promise<void> {
    try {
      const user = await this.userAuthRepository.findById(userId)
      if (!user) return

      // Tạo khóa tài khoản
      const lockKey = `user:${userId}:account_locked`
      await this.redisService.set(lockKey, 'true', 'EX', 60 * this.loginLockoutMinutes)

      // Ghi lại hoạt động khóa
      await this.logActivity({
        userId,
        type: UserActivityType.ACCOUNT_LOCKED,
        timestamp: Date.now(),
        ipAddress: activity.ipAddress,
        userAgent: activity.userAgent,
        deviceId: activity.deviceId,
        severity: ActivitySeverity.CRITICAL,
        details: {
          lockoutMinutes: this.loginLockoutMinutes,
          reason: 'Quá nhiều lần đăng nhập thất bại'
        }
      })

      // Thông báo cho người dùng
      await this.emailService.sendSecurityAlertEmail(SecurityAlertType.ACCOUNT_LOCKED, user.email, {
        userName: user.userProfile?.firstName || user.email.split('@')[0],
        ipAddress: activity.ipAddress || 'Unknown',
        location: activity.location || 'Unknown location',
        time: new Date().toISOString(),
        lockoutMinutes: this.loginLockoutMinutes
      })

      this.logger.warn(`[lockAccount] Account locked for user ${userId} due to too many login failures`)
    } catch (error) {
      this.logger.error(`[lockAccount] Error: ${error.message}`)
    }
  }

  /**
   * Kiểm tra xem tài khoản có bị khóa không
   */
  async isAccountLocked(userId: number): Promise<boolean> {
    const lockKey = `user:${userId}:account_locked`
    return (await this.redisService.exists(lockKey)) > 0
  }

  /**
   * Mở khóa tài khoản
   */
  async unlockAccount(userId: number, adminId?: number): Promise<void> {
    // Xóa trạng thái khóa
    const lockKey = `user:${userId}:account_locked`
    await this.redisService.del(lockKey)

    // Ghi lại hoạt động mở khóa
    await this.logActivity({
      userId,
      type: UserActivityType.ACCOUNT_UNLOCKED,
      timestamp: Date.now(),
      severity: ActivitySeverity.INFO,
      details: {
        unlockedBy: adminId || 'system',
        automaticUnlock: !adminId
      }
    })

    this.logger.debug(`[unlockAccount] Account unlocked for user ${userId}`)
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

      // Kiểm tra xem đã thông báo gần đây chưa
      const notificationKey = `user:${userId}:suspicious_notification:${rule.name}`
      const lastNotification = await this.redisService.get(notificationKey)

      if (lastNotification) {
        // Đã thông báo trong vòng 24h gần đây, không gửi tiếp
        return
      }

      // Gửi email thông báo
      await this.emailService.sendSecurityAlertEmail(SecurityAlertType.SUSPICIOUS_ACTIVITY, user.email, {
        userName: user.userProfile?.firstName || user.email.split('@')[0],
        activityType: this.getUserFriendlyActivityName(activity.type),
        ipAddress: activity.ipAddress || 'Unknown',
        location: activity.location || 'Unknown location',
        time: new Date().toISOString(),
        ruleName: rule.name,
        severity: rule.severity
      })

      // Đánh dấu đã thông báo (trong 24h)
      await this.redisService.set(notificationKey, Date.now().toString(), 'EX', 60 * 60 * 24)

      this.logger.debug(
        `[notifyUserAboutSuspiciousActivity] Notification sent to user ${userId} about rule violation: ${rule.name}`
      )
    } catch (error) {
      this.logger.error(`[notifyUserAboutSuspiciousActivity] Error: ${error.message}`)
    }
  }

  /**
   * Lấy tên người dùng thân thiện cho loại hoạt động
   */
  private getUserFriendlyActivityName(activityType: UserActivityType): string {
    switch (activityType) {
      case UserActivityType.LOGIN_ATTEMPT:
        return 'Cố gắng đăng nhập'
      case UserActivityType.LOGIN_FAILURE:
        return 'Đăng nhập thất bại'
      case UserActivityType.LOGIN_SUCCESS:
        return 'Đăng nhập thành công'
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
        return 'Cố gắng khôi phục tài khoản'
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
   * Lấy lịch sử hoạt động của người dùng
   */
  async getUserActivityHistory(
    userId: number,
    limit: number = 20,
    activityTypes?: UserActivityType[]
  ): Promise<UserActivity[]> {
    try {
      const activityKey = `user:${userId}:activities`
      const activities = await this.redisService.lrange(activityKey, 0, limit - 1)

      if (!activities || activities.length === 0) return []

      const parsedActivities: UserActivity[] = []

      for (const activityJson of activities) {
        try {
          const activity = JSON.parse(activityJson) as UserActivity

          // Lọc theo loại hoạt động nếu có
          if (!activityTypes || activityTypes.includes(activity.type)) {
            parsedActivities.push(activity)
          }
        } catch (error) {
          this.logger.error(`[getUserActivityHistory] Error parsing activity: ${error.message}`)
        }
      }

      return parsedActivities
    } catch (error) {
      this.logger.error(`[getUserActivityHistory] Error: ${error.message}`)
      return []
    }
  }
}
