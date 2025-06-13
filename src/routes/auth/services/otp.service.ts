import { Injectable, Logger, Inject, HttpException } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'

import { RedisService } from 'src/shared/providers/redis/redis.service'
import { RedisKeyManager } from 'src/shared/providers/redis/redis-keys.utils'
import { EmailService, OtpEmailProps } from 'src/shared/services/email.service'
import { GeolocationService } from 'src/shared/services/geolocation.service'
import { UserAgentService } from 'src/shared/services/user-agent.service'

import { UserRepository } from 'src/routes/user/user.repository'

import { TypeOfVerificationCodeType, OTP_LENGTH, TypeOfVerificationCode } from 'src/routes/auth/auth.constants'
import {
  EMAIL_SERVICE,
  GEOLOCATION_SERVICE,
  REDIS_SERVICE,
  USER_AGENT_SERVICE
} from 'src/shared/constants/injection.tokens'

import { OtpData, IOTPService } from 'src/routes/auth/auth.types'
import { AuthError } from 'src/routes/auth/auth.error'
import { I18nContext } from 'nestjs-i18n'

@Injectable()
export class OtpService implements IOTPService {
  private readonly logger = new Logger(OtpService.name)

  constructor(
    private readonly configService: ConfigService,
    private readonly userRepository: UserRepository,

    @Inject(REDIS_SERVICE) private readonly redisService: RedisService,
    @Inject(EMAIL_SERVICE) private readonly emailService: EmailService,
    @Inject(GEOLOCATION_SERVICE) private readonly geolocationService: GeolocationService,
    @Inject(USER_AGENT_SERVICE) private readonly userAgentService: UserAgentService
  ) {}

  generateOTP(length: number = OTP_LENGTH): string {
    const digits = '0123456789'
    let OTP = ''
    for (let i = 0; i < length; i++) {
      OTP += digits[Math.floor(Math.random() * 10)]
    }
    return OTP
  }

  private getOtpKey(type: TypeOfVerificationCodeType, identifier: string): string {
    return RedisKeyManager.getOtpDataKey(type, identifier)
  }

  private async _buildOtpEmailContext(
    targetEmail: string,
    type: TypeOfVerificationCodeType,
    otpCode: string,
    lang: 'vi' | 'en',
    metadata?: Record<string, any>
  ): Promise<Omit<OtpEmailProps, 'headline' | 'content' | 'codeLabel' | 'validity' | 'disclaimer' | 'greeting'>> {
    let userName = metadata?.userName
    if (!userName && type !== TypeOfVerificationCode.REGISTER) {
      const user = await this.userRepository.findByEmailWithDetails(targetEmail)
      if (user) {
        userName = user.userProfile?.username
      }
    }

    const details = []
    if (metadata?.ipAddress && metadata?.userAgent) {
      const locationResult = await this.geolocationService.getLocationFromIP(metadata.ipAddress)
      const uaInfo = this.userAgentService.parse(metadata.userAgent)
      const localeForDate = lang === 'vi' ? 'vi-VN' : 'en-US'

      details.push({
        label: 'email.Email.common.details.time',
        value: new Date().toLocaleString(localeForDate, {
          timeZone: locationResult.timezone || 'Asia/Ho_Chi_Minh',
          dateStyle: 'full',
          timeStyle: 'long'
        })
      })
      details.push({
        label: 'email.Email.common.details.ipAddress',
        value: metadata.ipAddress
      })
      details.push({
        label: 'email.Email.common.details.device',
        value: `${uaInfo.browser} on ${uaInfo.os}`
      })
    }

    return {
      userName: userName || targetEmail.split('@')[0],
      code: otpCode,
      lang,
      details
    }
  }

  async sendOTP(
    targetEmail: string,
    type: TypeOfVerificationCodeType,
    metadata?: Record<string, any>
  ): Promise<{ message: string; data: { verificationType: string; otpCode?: string } }> {
    try {
      const otpCode = this.generateOTP()
      const otpKey = this.getOtpKey(type, targetEmail)
      const otpExpirySeconds = this.configService.get<number>('security.otpExpirySeconds', 300)

      const otpDataForRedis: Record<string, string | number> = {
        code: otpCode,
        attempts: 0,
        createdAt: Date.now()
      }

      if (metadata) {
        otpDataForRedis.metadata = typeof metadata === 'object' ? JSON.stringify(metadata) : String(metadata)
      }

      await this.redisService.hset(otpKey, otpDataForRedis)
      await this.redisService.expire(otpKey, otpExpirySeconds)

      try {
        if (this.emailService) {
          const preferredLang = I18nContext.current()?.lang ?? metadata?.lang
          const safeLang: 'vi' | 'en' = preferredLang === 'en' || preferredLang === 'vi' ? preferredLang : 'vi'
          const emailContext = await this._buildOtpEmailContext(targetEmail, type, otpCode, safeLang, metadata)
          await this.emailService.sendOtpEmail(targetEmail, type, emailContext)
        }
      } catch {
        throw AuthError.OTPSendingFailed()
      }

      const responseData: { verificationType: string; otpCode?: string } = {
        verificationType: 'OTP'
      }

      if (this.configService.get('NODE_ENV') !== 'production') {
        responseData.otpCode = otpCode
      }

      return {
        message: 'auth.success.otp.sent',
        data: responseData
      }
    } catch (error) {
      if (error instanceof HttpException) {
        throw error
      }
      throw AuthError.InternalServerError('Failed to send OTP')
    }
  }

  async verifyOTP(emailToVerifyAgainst: string, code: string, type: TypeOfVerificationCodeType): Promise<boolean> {
    const otpKey = this.getOtpKey(type, emailToVerifyAgainst)

    try {
      const otpData = await this.getOtpData(otpKey)

      await this.checkOtpMaxAttempts(otpKey)

      await this.checkOtpExpiry(otpKey, otpData.createdAt)

      if (otpData.code !== code) {
        await this.redisService.hincrby(otpKey, 'attempts', 1)
        throw AuthError.InvalidOTP()
      }

      await this.redisService.del(otpKey)
      return true
    } catch (error) {
      if (error instanceof HttpException) throw error

      throw AuthError.InvalidOTP()
    }
  }

  private async getOtpData(otpKey: string): Promise<OtpData> {
    const rawOtpData = await this.redisService.hgetall(otpKey)
    if (!rawOtpData || Object.keys(rawOtpData).length === 0) {
      throw AuthError.OTPExpired()
    }

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
      } catch (_e) {
        void _e
        otpData.metadata = { raw: rawOtpData.metadata }
      }
    }

    return otpData
  }

  private async checkOtpMaxAttempts(otpKey: string): Promise<void> {
    const maxAttempts = this.configService.get<number>('OTP_MAX_ATTEMPTS', 5)
    const currentAttempts = parseInt((await this.redisService.hget(otpKey, 'attempts')) || '0', 10)

    if (currentAttempts >= maxAttempts) {
      await this.redisService.del(otpKey)
      throw AuthError.TooManyOTPAttempts()
    }
  }

  private async checkOtpExpiry(otpKey: string, createdAtTimestamp: number): Promise<void> {
    const otpExpirySeconds = this.configService.get<number>('OTP_EXPIRY_SECONDS', 300)

    if (Date.now() > createdAtTimestamp + otpExpirySeconds * 1000) {
      await this.redisService.del(otpKey)
      throw AuthError.OTPExpired()
    }
  }
}
