import { Injectable, Logger, Inject, HttpException } from '@nestjs/common'
import { JwtService } from '@nestjs/jwt'
import { RedisService } from 'src/shared/services/redis.service'
import { TypeOfVerificationCodeType, OTP_LENGTH, TypeOfVerificationCode } from 'src/routes/auth/auth.constants'
import { OtpData, IOTPService } from 'src/routes/auth/auth.types'
import { ConfigService } from '@nestjs/config'
import { AuthError } from 'src/routes/auth/auth.error'
import { I18nService, I18nContext } from 'nestjs-i18n'
import { EMAIL_SERVICE, GEOLOCATION_SERVICE, USER_AGENT_SERVICE } from 'src/shared/constants/injection.tokens'
import { EmailService, OtpEmailProps } from 'src/shared/services/email.service'
import { RedisKeyManager } from 'src/shared/utils/redis-keys.utils'
import { GeolocationService } from 'src/shared/services/geolocation.service'
import { UserAgentService } from 'src/shared/services/user-agent.service'
import { I18nTranslations } from 'src/generated/i18n.generated'
import { UserRepository } from 'src/routes/user/user.repository'

@Injectable()
export class OtpService implements IOTPService {
  private readonly logger = new Logger(OtpService.name)

  constructor(
    private readonly redisService: RedisService,
    @Inject(EMAIL_SERVICE) private readonly emailService: EmailService,
    private readonly jwtService: JwtService,
    private readonly i18nService: I18nService<I18nTranslations>,
    private readonly configService: ConfigService,
    @Inject(GEOLOCATION_SERVICE) private readonly geolocationService: GeolocationService,
    @Inject(USER_AGENT_SERVICE) private readonly userAgentService: UserAgentService,
    private readonly userRepository: UserRepository
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
          this.logger.log(`[sendOTP] Email OTP cho mục đích ${type} đã được gửi đến ${targetEmail} ${otpCode}`)
        } else {
          this.logger.warn('EmailService không được inject, không thể gửi email OTP.')
        }
      } catch (error) {
        this.logger.error(`[sendOTP] Error sending OTP email to ${targetEmail}: ${error.message}`, error.stack)
        throw AuthError.OTPSendingFailed()
      }

      const responseData: { verificationType: string; otpCode?: string } = {
        verificationType: 'OTP'
      }

      if (this.configService.get('NODE_ENV') !== 'production') {
        responseData.otpCode = otpCode
      }

      return {
        message: this.i18nService.t('auth.success.otp.sent'),
        data: responseData
      }
    } catch (error) {
      this.logger.error(`[sendOTP] Lỗi: ${error.message}`, error.stack)
      if (error instanceof HttpException) {
        throw error
      }
      throw AuthError.InternalServerError('Failed to send OTP')
    }
  }

  /**
   * Xác minh mã OTP
   * @returns `true` nếu hợp lệ, ngược lại sẽ throw exception
   */
  async verifyOTP(emailToVerifyAgainst: string, code: string, type: TypeOfVerificationCodeType): Promise<boolean> {
    const otpKey = this.getOtpKey(type, emailToVerifyAgainst)
    this.logger.debug(`Verifying OTP for key: ${otpKey}`)

    try {
      // Lấy dữ liệu OTP từ Redis
      const otpData = await this.getOtpData(otpKey)

      // Kiểm tra số lần thử
      await this.checkOtpMaxAttempts(otpKey)

      // Kiểm tra thời gian hết hạn
      await this.checkOtpExpiry(otpKey, otpData.createdAt)

      // So sánh mã
      if (otpData.code !== code) {
        this.logger.warn(`Invalid OTP attempt for key ${otpKey}.`)
        // Ghi lại lần thử thất bại
        await this.redisService.hincrby(otpKey, 'attempts', 1)
        throw AuthError.InvalidOTP()
      }

      // Xóa OTP sau khi xác minh thành công
      await this.redisService.del(otpKey)
      this.logger.log(`OTP for key ${otpKey} verified successfully and deleted.`)
      return true
    } catch (error) {
      if (error instanceof HttpException) throw error

      this.logger.error(`Error during OTP verification for key ${otpKey}: ${error.message}`, error.stack)
      // Throw một lỗi chung để không tiết lộ chi tiết
      throw AuthError.InvalidOTP()
    }
  }

  /**
   * Lấy dữ liệu OTP từ Redis
   */
  private async getOtpData(otpKey: string): Promise<OtpData> {
    const rawOtpData = await this.redisService.hgetall(otpKey)
    if (!rawOtpData || Object.keys(rawOtpData).length === 0) {
      this.logger.warn(`OTP data not found or empty for key: ${otpKey}. Assuming expired.`)
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
    const maxAttempts = this.configService.get<number>('OTP_MAX_ATTEMPTS', 5)
    const currentAttempts = parseInt((await this.redisService.hget(otpKey, 'attempts')) || '0', 10)

    if (currentAttempts >= maxAttempts) {
      this.logger.warn(`Max OTP attempts reached for key: ${otpKey}. Deleting OTP.`)
      // Xóa OTP để ngăn chặn brute force
      await this.redisService.del(otpKey)
      throw AuthError.TooManyOTPAttempts()
    }
  }

  /**
   * Kiểm tra OTP hết hạn
   */
  private async checkOtpExpiry(otpKey: string, createdAtTimestamp: number): Promise<void> {
    const otpExpirySeconds = this.configService.get<number>('OTP_EXPIRY_SECONDS', 300)

    if (Date.now() > createdAtTimestamp + otpExpirySeconds * 1000) {
      this.logger.warn(`OTP has expired for key: ${otpKey}. Deleting.`)
      // Xóa OTP đã hết hạn
      await this.redisService.del(otpKey)
      throw AuthError.OTPExpired()
    }
  }
}
