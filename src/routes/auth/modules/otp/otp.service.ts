import { Injectable, Logger, Inject } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { I18nService } from 'nestjs-i18n'
import { IOTPService } from 'src/shared/types/auth.types'
import { REDIS_SERVICE, EMAIL_SERVICE } from 'src/shared/constants/injection.tokens'
import { EmailService } from 'src/shared/services/email.service'
import { RedisService } from 'src/shared/providers/redis/redis.service'
import { RedisKeyManager } from 'src/shared/utils/redis-keys.utils'
import { AuthError } from 'src/routes/auth/auth.error'
import { OTP_LENGTH, OTP_COOLDOWN_SECONDS, TypeOfVerificationCodeType } from 'src/shared/constants/auth.constants'
import { OtpData } from 'src/routes/auth/auth.types'
import * as crypto from 'crypto'
import { validate } from 'class-validator'
import { IsEmail, Length } from 'class-validator'

interface NotificationMetadata {
  emailTitle?: string
  templateId?: string
  language?: string
}

@Injectable()
export class OtpService implements IOTPService {
  private readonly logger = new Logger(OtpService.name)

  constructor(
    @Inject(REDIS_SERVICE) private readonly redisService: RedisService,
    @Inject(EMAIL_SERVICE) private readonly emailService: EmailService,
    private readonly configService: ConfigService,
    private readonly i18nService: I18nService
  ) {}

  /**
   * Generate a secure OTP
   */
  generateOTP(length: number = OTP_LENGTH): string {
    const bytes = crypto.randomBytes(length)
    const digits = '0123456789'
    let otp = ''
    for (let i = 0; i < length; i++) {
      otp += digits[bytes[i] % 10]
    }
    return otp
  }

  /**
   * Get Redis key for OTP
   */
  private getOtpKey(type: TypeOfVerificationCodeType, identifier: string): string {
    return RedisKeyManager.otpKey(type, identifier)
  }

  /**
   * Get Redis key for OTP cooldown
   */
  private getOtpLastSentKey(identifierForCooldown: string, purpose: TypeOfVerificationCodeType): string {
    return RedisKeyManager.otpLastSentKey(identifierForCooldown, purpose)
  }

  /**
   * Validate email and OTP code
   */
  private async validateInput(email: string, code?: string): Promise<void> {
    class ValidationDto {
      @IsEmail()
      email: string

      @Length(OTP_LENGTH, OTP_LENGTH, { message: `OTP must be ${OTP_LENGTH} digits` })
      code?: string
    }

    const dto = new ValidationDto()
    dto.email = email
    if (code) dto.code = code

    const errors = await validate(dto)
    if (errors.length > 0) {
      throw AuthError.InvalidOTP()
    }
  }

  /**
   * Send OTP to target email
   */
  async sendOTP(
    targetEmail: string,
    type: TypeOfVerificationCodeType,
    userIdForCooldownAndOtpData?: number,
    metadata?: NotificationMetadata
  ): Promise<{ message: string; otpCode: string }> {
    return this.handleError(
      async () => {
        await this.validateInput(targetEmail)

        const identifierForCooldown = userIdForCooldownAndOtpData
          ? `user:${userIdForCooldownAndOtpData}`
          : `email:${targetEmail}`
        const otpLastSentKey = this.getOtpLastSentKey(identifierForCooldown, type)

        await this.checkOtpCooldown(otpLastSentKey)

        const otpCode = this.generateOTP()
        const otpKey = this.getOtpKey(type, targetEmail)
        const otpExpirySeconds = this.configService.get<number>('security.otpExpirySeconds', 300)

        const otpData: OtpData = {
          code: otpCode,
          attempts: 0,
          createdAt: Date.now(),
          ...(userIdForCooldownAndOtpData && { userId: userIdForCooldownAndOtpData }),
          ...(metadata && { metadata })
        }

        await this.redisService.hset(otpKey, this.serializeOtpData(otpData))
        await this.redisService.expire(otpKey, otpExpirySeconds)

        await this.emailService.sendOtpEmail({
          email: targetEmail,
          otpCode,
          otpType: type,
          ...(metadata?.emailTitle && { title: metadata.emailTitle }),
          ...(metadata?.templateId && { templateId: metadata.templateId }),
          ...(metadata?.language && { language: metadata.language })
        })
        this.logger.log(`[sendOTP] OTP sent for purpose ${type} to ${targetEmail}`)

        await this.redisService.set(otpLastSentKey, Date.now().toString(), 'EX', OTP_COOLDOWN_SECONDS)

        return { message: this.i18nService.t('auth.Auth.Otp.SentSuccessfully'), otpCode }
      },
      'sendOTP',
      'Failed to send OTP'
    )
  }

  /**
   * Verify OTP
   */
  async verifyOTP(
    emailToVerifyAgainst: string,
    code: string,
    type: TypeOfVerificationCodeType,
    userIdForAudit?: number,
    ip?: string,
    userAgent?: string
  ): Promise<boolean> {
    return this.handleError(
      async () => {
        await this.validateInput(emailToVerifyAgainst, code)

        const otpKey = this.getOtpKey(type, emailToVerifyAgainst)
        const otpData = await this.getOtpData(otpKey)

        const maxAttempts = this.configService.get<number>('security.otpMaxAttempts', 5)
        const newAttempts = await this.redisService.hincrby(otpKey, 'attempts', 1)

        if (newAttempts > maxAttempts) {
          await this.redisService.del(otpKey)
          this.logger.warn(`[verifyOTP] OTP max attempts exceeded for key: ${otpKey}, attempts: ${newAttempts}`)
          throw AuthError.OTPMaxAttemptsExceeded()
        }

        if (otpData.code !== code) {
          this.logger.warn(`[verifyOTP] Invalid OTP code for ${emailToVerifyAgainst}`)
          throw AuthError.InvalidOTP()
        }

        await this.checkOtpExpiry(otpKey, otpData.createdAt)

        this.logger.log(`[verifyOTP] OTP verified successfully for ${emailToVerifyAgainst}, purpose: ${type}`)
        await this.redisService.del(otpKey)

        return true
      },
      'verifyOTP',
      'Failed to verify OTP'
    )
  }

  /**
   * Check OTP cooldown
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
   * Get OTP data from Redis
   */
  private async getOtpData(otpKey: string): Promise<OtpData> {
    const rawOtpData = await this.redisService.hgetall(otpKey)
    if (!rawOtpData || Object.keys(rawOtpData).length === 0) {
      this.logger.warn(`[getOtpData] OTP data not found or expired for key: ${otpKey}`)
      throw AuthError.OTPExpired()
    }

    const otpData: OtpData = {
      code: rawOtpData.code,
      attempts: parseInt(rawOtpData.attempts || '0', 10),
      createdAt: parseInt(rawOtpData.createdAt || '0', 10)
    }

    if (rawOtpData.userId) otpData.userId = parseInt(rawOtpData.userId, 10)
    if (rawOtpData.deviceId) otpData.deviceId = parseInt(rawOtpData.deviceId, 10)
    if (rawOtpData.metadata) {
      try {
        otpData.metadata = JSON.parse(rawOtpData.metadata)
      } catch {
        this.logger.warn(`[getOtpData] Invalid metadata format: ${rawOtpData.metadata}`)
        otpData.metadata = { raw: rawOtpData.metadata }
      }
    }

    return otpData
  }

  /**
   * Check OTP expiry
   */
  private async checkOtpExpiry(otpKey: string, createdAtTimestamp: number): Promise<void> {
    const otpExpirySeconds = this.configService.get<number>('security.otpExpirySeconds', 300)
    const elapsedSeconds = (Date.now() - createdAtTimestamp) / 1000

    if (elapsedSeconds > otpExpirySeconds) {
      await this.redisService.del(otpKey)
      this.logger.warn(`[checkOtpExpiry] OTP expired for key: ${otpKey}`)
      throw AuthError.OTPExpired()
    }
  }

  /**
   * Serialize OTP data for Redis storage
   */
  private serializeOtpData(otpData: OtpData): Record<string, string | number> {
    const serialized: Record<string, string | number> = {
      code: otpData.code,
      attempts: otpData.attempts,
      createdAt: otpData.createdAt
    }

    if (otpData.userId) serialized.userId = otpData.userId
    if (otpData.deviceId) serialized.deviceId = otpData.deviceId
    if (otpData.metadata) serialized.metadata = JSON.stringify(otpData.metadata)

    return serialized
  }

  /**
   * Handle errors with consistent logging and response
   */
  private async handleError<T>(
    operation: () => Promise<T>,
    methodName: string,
    defaultErrorMessage: string
  ): Promise<T> {
    try {
      return await operation()
    } catch (error) {
      this.logger.error(`[${methodName}] Error: ${error.message}`, error.stack)
      if (error instanceof AuthError) throw error
      throw AuthError.InternalServerError(defaultErrorMessage)
    }
  }
}
