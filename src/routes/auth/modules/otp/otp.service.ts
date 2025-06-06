import { Injectable, Logger, Inject, HttpException } from '@nestjs/common'
import { JwtService } from '@nestjs/jwt'
import { RedisService } from 'src/providers/redis/redis.service'
import { TypeOfVerificationCodeType, OTP_LENGTH, OTP_COOLDOWN_SECONDS } from 'src/shared/constants/auth.constants'
import { OtpData } from 'src/routes/auth/auth.types'
import { ConfigService } from '@nestjs/config'
import { AuthError } from 'src/routes/auth/auth.error'
import { I18nService } from 'nestjs-i18n'
import { IOTPService } from 'src/routes/auth/shared/auth.types'
import { REDIS_SERVICE, EMAIL_SERVICE } from 'src/shared/constants/injection.tokens'
import { EmailService } from 'src/routes/auth/shared/services/common/email.service'
import { RedisKeyManager } from 'src/shared/utils/redis-keys.utils'
import { DeviceRepository } from 'src/routes/auth/shared/repositories'

@Injectable()
export class OtpService implements IOTPService {
  private readonly logger = new Logger(OtpService.name)

  constructor(
    @Inject(REDIS_SERVICE) private readonly redisService: RedisService,
    @Inject(EMAIL_SERVICE) private readonly emailService: EmailService,
    private readonly jwtService: JwtService,
    private readonly i18nService: I18nService,
    private readonly configService: ConfigService,
    private readonly deviceRepository: DeviceRepository
  ) {}

  /**
   * Tạo mã OTP
   */
  generateOTP(length: number = OTP_LENGTH): string {
    const digits = '0123456789'
    let OTP = ''
    for (let i = 0; i < length; i++) {
      OTP += digits[Math.floor(Math.random() * 10)]
    }
    return OTP
  }

  /**
   * Tạo key cho Redis OTP
   */
  private getOtpKey(type: TypeOfVerificationCodeType, identifier: string): string {
    return RedisKeyManager.otpKey(type, identifier)
  }

  /**
   * Tạo key cho cooldown của OTP
   */
  private getOtpLastSentKey(identifierForCooldown: string, purpose: TypeOfVerificationCodeType): string {
    return RedisKeyManager.otpLastSentKey(identifierForCooldown, purpose)
  }

  /**
   * Gửi OTP
   */
  async sendOTP(
    targetEmail: string,
    type: TypeOfVerificationCodeType,
    userIdForCooldownAndOtpData?: number,
    metadata?: Record<string, any>
  ): Promise<{ message: string; otpCode: string }> {
    try {
      const identifierForCooldown = userIdForCooldownAndOtpData
        ? `user:${userIdForCooldownAndOtpData}`
        : `email:${targetEmail}`
      const otpLastSentKey = this.getOtpLastSentKey(identifierForCooldown, type)

      await this.checkOtpCooldown(otpLastSentKey)

      const otpCode = this.generateOTP()
      const otpKey = this.getOtpKey(type, targetEmail)
      const otpExpirySeconds = this.configService.get<number>('security.otpExpirySeconds', 300)

      const otpDataForRedis: Record<string, string | number> = {
        code: otpCode,
        attempts: 0,
        createdAt: Date.now(),
        ...(userIdForCooldownAndOtpData && { userId: userIdForCooldownAndOtpData })
      }

      // Xử lý metadata là object hoặc giá trị khác
      if (metadata) {
        otpDataForRedis.metadata = typeof metadata === 'object' ? JSON.stringify(metadata) : String(metadata)
      }

      await this.redisService.hset(otpKey, otpDataForRedis)
      await this.redisService.expire(otpKey, otpExpirySeconds)

      try {
        await this.emailService.sendOtpEmail({
          email: targetEmail,
          otpCode,
          otpType: type,
          ...(metadata?.emailTitle && { title: metadata.emailTitle })
        })
        this.logger.log(`[sendOTP] Email OTP cho mục đích ${type} đã được gửi đến ${targetEmail}`)
      } catch (error) {
        this.logger.error(`[sendOTP] Lỗi gửi email OTP đến ${targetEmail}: ${error.message}`, error.stack)
        throw AuthError.InternalServerError('Failed to send OTP email.')
      }

      await this.redisService.set(otpLastSentKey, Date.now().toString(), 'EX', OTP_COOLDOWN_SECONDS)

      return { message: this.i18nService.t('auth.Auth.Otp.SentSuccessfully'), otpCode }
    } catch (error) {
      this.logger.error(`[sendOTP] Lỗi: ${error.message}`, error.stack)
      if (error instanceof AuthError) {
        throw error
      }
      throw AuthError.InternalServerError('Lỗi khi gửi OTP')
    }
  }

  /**
   * Kiểm tra thời gian chờ giữa các lần gửi OTP
   */
  private async checkOtpCooldown(otpLastSentKey: string): Promise<void> {
    const lastSentTimestamp = await this.redisService.get(otpLastSentKey)
    if (lastSentTimestamp) {
      const elapsedSeconds = (Date.now() - parseInt(lastSentTimestamp, 10)) / 1000
      const cooldown = this.configService.get<number>('security.otpCooldownSeconds', OTP_COOLDOWN_SECONDS)
      if (elapsedSeconds < cooldown) {
        const remainingSeconds = Math.ceil(cooldown - elapsedSeconds)
        this.logger.warn(`[checkOtpCooldown] OTP request blocked due to cooldown. ${remainingSeconds}s remaining.`)
        throw AuthError.OTPSendingLimited()
      }
    }
  }

  /**
   * Xác minh OTP
   */
  async verifyOTP(
    emailToVerifyAgainst: string,
    code: string,
    type: TypeOfVerificationCodeType,
    userIdForAudit?: number,
    ip?: string,
    userAgent?: string
  ): Promise<boolean> {
    try {
      if (!code || !emailToVerifyAgainst) {
        throw AuthError.InvalidOTP()
      }

      const otpKey = this.getOtpKey(type, emailToVerifyAgainst)
      const otpData = await this.getOtpData(otpKey)

      await this.checkOtpMaxAttempts(otpKey, otpData.attempts)

      if (otpData.code !== code) {
        await this.handleInvalidOtp(otpKey)
        throw AuthError.InvalidOTP()
      }

      await this.checkOtpExpiry(otpKey, otpData.createdAt)

      this.logger.log(`[verifyOTP] OTP xác thực thành công cho ${emailToVerifyAgainst}, mục đích: ${type}`)
      await this.redisService.del(otpKey)

      return true
    } catch (error) {
      this.logger.error(`[verifyOTP] Lỗi: ${error.message}`, error.stack)
      if (error instanceof AuthError) {
        throw error
      }
      throw AuthError.InternalServerError('Lỗi khi xác thực OTP')
    }
  }

  /**
   * Lấy dữ liệu OTP từ Redis
   */
  private async getOtpData(otpKey: string): Promise<OtpData> {
    const rawOtpData = await this.redisService.hgetall(otpKey)
    if (!rawOtpData || Object.keys(rawOtpData).length === 0) {
      this.logger.warn(`[getOtpData] OTP data not found or expired for key: ${otpKey}`)
      throw AuthError.OTPExpired()
    }

    // Parse rawOtpData into OtpData structure
    const otpData: OtpData = {
      code: rawOtpData.code,
      attempts: parseInt(rawOtpData.attempts || '0', 10),
      createdAt: parseInt(rawOtpData.createdAt || '0', 10)
    }

    if (rawOtpData.userId) {
      otpData.userId = parseInt(rawOtpData.userId, 10)
    }

    if (rawOtpData.deviceId) {
      otpData.deviceId = parseInt(rawOtpData.deviceId, 10)
    }

    if (rawOtpData.metadata) {
      try {
        otpData.metadata = JSON.parse(rawOtpData.metadata)
      } catch (e) {
        this.logger.warn(`[getOtpData] Failed to parse OTP metadata: ${rawOtpData.metadata}`)
        otpData.metadata = { raw: rawOtpData.metadata }
      }
    }

    return otpData
  }

  /**
   * Kiểm tra số lần thử tối đa
   */
  private async checkOtpMaxAttempts(otpKey: string, currentAttempts: number): Promise<void> {
    const maxAttempts = this.configService.get('security.otpMaxAttempts', 5)

    // Tăng số lần thử một cách an toàn bằng HINCRBY
    const newAttempts = await this.redisService.hincrby(otpKey, 'attempts', 1)

    if (newAttempts > maxAttempts) {
      this.logger.warn(`[checkOtpMaxAttempts] OTP max attempts exceeded for key: ${otpKey}, attempts: ${newAttempts}`)
      // Xóa OTP để ngăn chặn brute force
      await this.redisService.del(otpKey)
      throw AuthError.OTPMaxAttemptsExceeded()
    }
  }

  /**
   * Xử lý OTP không hợp lệ
   */
  private async handleInvalidOtp(otpKey: string): Promise<void> {
    await this.redisService.hincrby(otpKey, 'attempts', 1)
  }

  /**
   * Kiểm tra OTP hết hạn
   */
  private async checkOtpExpiry(otpKey: string, createdAtTimestamp: number): Promise<void> {
    const otpExpirySeconds = this.configService.get<number>('security.otpExpirySeconds', 300)
    const now = Date.now()
    const elapsedSeconds = (now - createdAtTimestamp) / 1000

    if (elapsedSeconds > otpExpirySeconds) {
      this.logger.warn(`[checkOtpExpiry] OTP expired for key: ${otpKey}`)
      // Xóa OTP đã hết hạn
      await this.redisService.del(otpKey)
      throw AuthError.OTPExpired()
    }
  }
}
