import { Injectable, Logger, Inject, HttpException } from '@nestjs/common'
import { JwtService } from '@nestjs/jwt'
import { RedisService } from 'src/shared/services/redis.service'
import { TypeOfVerificationCodeType, OTP_LENGTH, TypeOfVerificationCode } from 'src/routes/auth/auth.constants'
import { OtpData, IOTPService } from 'src/shared/types/auth.types'
import { ConfigService } from '@nestjs/config'
import { AuthError } from 'src/routes/auth/auth.error'
import { I18nService, I18nContext } from 'nestjs-i18n'
import { EMAIL_SERVICE, GEOLOCATION_SERVICE, USER_AGENT_SERVICE } from 'src/shared/constants/injection.tokens'
import { EmailService, OtpEmailProps } from 'src/shared/services/email.service'
import { RedisKeyManager } from 'src/shared/utils/redis-keys.utils'
import { UserAuthRepository } from 'src/routes/auth/repositories'
import { GeolocationService } from 'src/shared/services/geolocation.service'
import { UserAgentService } from 'src/shared/services/user-agent.service'

@Injectable()
export class OtpService implements IOTPService {
  private readonly logger = new Logger(OtpService.name)

  constructor(
    private readonly redisService: RedisService,
    @Inject(EMAIL_SERVICE) private readonly emailService: EmailService,
    private readonly jwtService: JwtService,
    private readonly i18nService: I18nService,
    private readonly configService: ConfigService,
    @Inject(GEOLOCATION_SERVICE) private readonly geolocationService: GeolocationService,
    @Inject(USER_AGENT_SERVICE) private readonly userAgentService: UserAgentService,
    private readonly userAuthRepository: UserAuthRepository
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
      const user = await this.userAuthRepository.findByEmail(targetEmail)
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
        label: this.i18nService.t('email.Email.common.details.time', { lang }),
        value: new Date().toLocaleString(localeForDate, {
          timeZone: locationResult.timezone || 'Asia/Ho_Chi_Minh',
          dateStyle: 'full',
          timeStyle: 'long'
        })
      })
      details.push({
        label: this.i18nService.t('email.Email.common.details.ipAddress', { lang }),
        value: metadata.ipAddress
      })
      details.push({
        label: this.i18nService.t('email.Email.common.details.device', { lang }),
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

  /**
   * Gửi OTP
   */
  async sendOTP(
    targetEmail: string,
    type: TypeOfVerificationCodeType,
    metadata?: Record<string, any>
  ): Promise<{ message: string; otpCode: string }> {
    try {
      const otpCode = this.generateOTP()
      const otpKey = this.getOtpKey(type, targetEmail)
      const otpExpirySeconds = this.configService.get<number>('security.otpExpirySeconds', 300)

      const otpDataForRedis: Record<string, string | number> = {
        code: otpCode,
        attempts: 0,
        createdAt: Date.now()
      }

      // Xử lý metadata là object hoặc giá trị khác
      if (metadata) {
        otpDataForRedis.metadata = typeof metadata === 'object' ? JSON.stringify(metadata) : String(metadata)
      }

      await this.redisService.hset(otpKey, otpDataForRedis)
      await this.redisService.expire(otpKey, otpExpirySeconds)

      // Gửi email chứa mã OTP
      try {
        if (this.emailService) {
          const preferredLang = I18nContext.current()?.lang ?? metadata?.lang
          const safeLang: 'vi' | 'en' = preferredLang === 'en' || preferredLang === 'vi' ? preferredLang : 'vi'
          const emailContext = await this._buildOtpEmailContext(targetEmail, type, otpCode, safeLang, metadata)
          await this.emailService.sendOtpEmail(targetEmail, type, emailContext)
          this.logger.log(`[sendOTP] Email OTP cho mục đích ${type} đã được gửi đến ${targetEmail}`)
        } else {
          this.logger.warn('EmailService không được inject, không thể gửi email OTP.')
        }
      } catch (error) {
        this.logger.error(`[sendOTP] Lỗi gửi email OTP đến ${targetEmail}: ${error.message}`, error.stack)
        throw AuthError.OTPSendingFailed()
      }

      const message = this.i18nService.t('auth.Auth.Otp.SentSuccessfully')

      return { message, otpCode }
    } catch (error) {
      this.logger.error(`[sendOTP] Lỗi: ${error.message}`, error.stack)
      if (error instanceof HttpException) {
        throw error
      }
      throw AuthError.InternalServerError('Failed to send OTP')
    }
  }

  /**
   * Xác minh OTP
   */
  async verifyOTP(
    emailToVerifyAgainst: string,
    code: string,
    type: TypeOfVerificationCodeType,
    _userIdForAudit?: number,
    _ip?: string,
    _userAgent?: string
  ): Promise<boolean> {
    void _userIdForAudit
    void _ip
    void _userAgent
    try {
      if (!code || !emailToVerifyAgainst) {
        throw AuthError.InvalidOTP()
      }

      const otpKey = this.getOtpKey(type, emailToVerifyAgainst)
      const otpData = await this.getOtpData(otpKey)

      // Chỉ kiểm tra và tăng số lần thử khi mã OTP không chính xác
      if (otpData.code !== code) {
        await this.checkOtpMaxAttempts(otpKey) // Tăng và kiểm tra số lần thử
        throw AuthError.InvalidOTP()
      }

      await this.checkOtpExpiry(otpKey, otpData.createdAt)

      this.logger.log(`[verifyOTP] OTP xác thực thành công cho ${emailToVerifyAgainst}, mục đích: ${type}`)
      await this.redisService.del(otpKey)

      return true
    } catch (error) {
      this.logger.error(`[verifyOTP] Lỗi: ${error.message}`, error.stack)
      if (error instanceof HttpException) {
        throw error
      }
      throw AuthError.InternalServerError('Failed to verify OTP')
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
      } catch (_e) {
        void _e
        this.logger.warn(`[getOtpData] Failed to parse OTP metadata: ${rawOtpData.metadata}`)
        otpData.metadata = { raw: rawOtpData.metadata }
      }
    }

    return otpData
  }

  /**
   * Kiểm tra số lần thử tối đa
   */
  private async checkOtpMaxAttempts(otpKey: string): Promise<void> {
    const maxAttempts = this.configService.get('security.otpMaxAttempts', 5)

    // Tăng số lần thử một cách an toàn bằng HINCRBY
    const newAttempts = await this.redisService.hincrby(otpKey, 'attempts', 1)

    if (newAttempts >= maxAttempts) {
      this.logger.warn(`[checkOtpMaxAttempts] OTP max attempts exceeded for key: ${otpKey}, attempts: ${newAttempts}`)
      // Xóa OTP để ngăn chặn brute force
      await this.redisService.del(otpKey)
      throw AuthError.TooManyOTPAttempts()
    }
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
