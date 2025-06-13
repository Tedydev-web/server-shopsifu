// ================================================================
// NestJS Dependencies
// ================================================================
import { Injectable, Logger, Inject, HttpException } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'

// ================================================================
// External Libraries
// ================================================================

// ================================================================
// Internal Services & Types
// ================================================================
import { RedisService } from 'src/shared/providers/redis/redis.service'
import { RedisKeyManager } from 'src/shared/providers/redis/redis-keys.utils'
import { EmailService, OtpEmailProps } from 'src/shared/services/email.service'
import { GeolocationService } from 'src/shared/services/geolocation.service'
import { UserAgentService } from 'src/shared/services/user-agent.service'

// ================================================================
// Repositories
// ================================================================
import { UserRepository } from 'src/routes/user/user.repository'

// ================================================================
// Constants & Injection Tokens
// ================================================================
import { TypeOfVerificationCodeType, OTP_LENGTH, TypeOfVerificationCode } from 'src/routes/auth/auth.constants'
import {
  EMAIL_SERVICE,
  GEOLOCATION_SERVICE,
  REDIS_SERVICE,
  USER_AGENT_SERVICE
} from 'src/shared/constants/injection.tokens'

// ================================================================
// Types & Interfaces
// ================================================================
import { OtpData, IOTPService } from 'src/routes/auth/auth.types'
import { AuthError } from 'src/routes/auth/auth.error'
import { I18nContext } from 'nestjs-i18n'

/**
 * Service quản lý OTP (One-Time Password) cho các quy trình xác thực
 * - Tạo và gửi mã OTP qua email
 * - Xác minh mã OTP từ người dùng
 * - Quản lý thời gian sống và giới hạn thử lại
 * - Hỗ trợ đa ngôn ngữ cho email OTP
 */

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

  // ================================================================
  // Public Methods - OTP Generation & Verification
  // ================================================================

  /**
   * Tạo mã OTP ngẫu nhiên gồm các chữ số
   * Sử dụng thuật toán random để tạo chuỗi số ngẫu nhiên
   * @param length - Độ dài mã OTP (mặc định từ constants)
   * @returns Chuỗi OTP gồm các chữ số
   */
  generateOTP(length: number = OTP_LENGTH): string {
    const digits = '0123456789'
    let OTP = ''
    for (let i = 0; i < length; i++) {
      OTP += digits[Math.floor(Math.random() * 10)]
    }
    return OTP
  }

  // ================================================================
  // Private Methods - Redis Key Management
  // ================================================================

  /**
   * Tạo Redis key cho việc lưu trữ OTP data
   * Sử dụng pattern chuẩn để đảm bảo tính nhất quán
   * @param type - Loại verification code
   * @param identifier - Định danh (thường là email)
   * @returns Redis key string
   */
  private getOtpKey(type: TypeOfVerificationCodeType, identifier: string): string {
    return RedisKeyManager.getOtpDataKey(type, identifier)
  }

  // ================================================================
  // Private Methods - Email Context Building
  // ================================================================

  /**
   * Xây dựng context cho email OTP với thông tin chi tiết về device và location
   * Bao gồm thông tin về thiết bị, vị trí địa lý, và metadata khác
   * @param targetEmail - Email đích
   * @param type - Loại verification
   * @param otpCode - Mã OTP
   * @param lang - Ngôn ngữ email ('vi' | 'en')
   * @param metadata - Metadata bổ sung (IP, userAgent, v.v.)
   * @returns Context object cho email template
   */
  private async _buildOtpEmailContext(
    targetEmail: string,
    type: TypeOfVerificationCodeType,
    otpCode: string,
    lang: 'vi' | 'en',
    metadata?: Record<string, any>
  ): Promise<Omit<OtpEmailProps, 'headline' | 'content' | 'codeLabel' | 'validity' | 'disclaimer' | 'greeting'>> {
    // Lấy username từ metadata hoặc database
    let userName = metadata?.userName
    if (!userName && type !== TypeOfVerificationCode.REGISTER) {
      const user = await this.userRepository.findByEmailWithDetails(targetEmail)
      if (user) {
        userName = user.userProfile?.username
      }
    }

    // Xây dựng thông tin chi tiết về request (thời gian, IP, device)
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

  /**
   * Gửi mã OTP qua email
   * @param targetEmail - Email đích nhận OTP
   * @param type - Loại verification code
   * @param metadata - Thông tin bổ sung (IP, userAgent, userName, v.v.)
   * @returns Kết quả gửi OTP với verification type
   */
  async sendOTP(
    targetEmail: string,
    type: TypeOfVerificationCodeType,
    metadata?: Record<string, any>
  ): Promise<{ message: string; data: { verificationType: string; otpCode?: string } }> {
    try {
      // Tạo mã OTP và chuẩn bị lưu trữ Redis
      const otpCode = this.generateOTP()
      const otpKey = this.getOtpKey(type, targetEmail)
      const otpExpirySeconds = this.configService.get<number>('security.otpExpirySeconds', 300)

      const otpDataForRedis: Record<string, string | number> = {
        code: otpCode,
        attempts: 0,
        createdAt: Date.now()
      }

      // Serialize metadata để lưu vào Redis
      if (metadata) {
        otpDataForRedis.metadata = typeof metadata === 'object' ? JSON.stringify(metadata) : String(metadata)
      }

      // Lưu OTP vào Redis với thời gian hết hạn
      await this.redisService.hset(otpKey, otpDataForRedis)
      await this.redisService.expire(otpKey, otpExpirySeconds)

      // Gửi email chứa mã OTP
      try {
        if (this.emailService) {
          const preferredLang = I18nContext.current()?.lang ?? metadata?.lang
          const safeLang: 'vi' | 'en' = preferredLang === 'en' || preferredLang === 'vi' ? preferredLang : 'vi'
          const emailContext = await this._buildOtpEmailContext(targetEmail, type, otpCode, safeLang, metadata)
          await this.emailService.sendOtpEmail(targetEmail, type, emailContext)
          this.logger.log(`[sendOTP] OTP email sent to ${targetEmail} for purpose ${type}. Code: ${otpCode}`)
        } else {
          this.logger.warn('[sendOTP] EmailService not injected, cannot send OTP email.')
        }
      } catch (error) {
        this.logger.error(`[sendOTP] Error sending OTP email to ${targetEmail}: ${error.message}`, error.stack)
        throw AuthError.OTPSendingFailed()
      }

      const responseData: { verificationType: string; otpCode?: string } = {
        verificationType: 'OTP'
      }

      // Trả về OTP code ở development mode để dễ test
      if (this.configService.get('NODE_ENV') !== 'production') {
        responseData.otpCode = otpCode
      }

      return {
        message: 'auth.success.otp.sent',
        data: responseData
      }
    } catch (error) {
      this.logger.error(`[sendOTP] Lỗi gửi OTP: ${error.message}`, error.stack)
      if (error instanceof HttpException) {
        throw error
      }
      throw AuthError.InternalServerError('Failed to send OTP')
    }
  }

  /**
   * Xác minh mã OTP từ người dùng
   * Thực hiện các bước kiểm tra: tồn tại, hết hạn, số lần thử, so sánh mã
   * @param emailToVerifyAgainst - Email để xác minh OTP
   * @param code - Mã OTP từ người dùng nhập
   * @param type - Loại verification code
   * @returns `true` nếu hợp lệ, ngược lại sẽ throw exception
   */
  async verifyOTP(emailToVerifyAgainst: string, code: string, type: TypeOfVerificationCodeType): Promise<boolean> {
    const otpKey = this.getOtpKey(type, emailToVerifyAgainst)
    this.logger.debug(`[verifyOTP] Xác minh OTP cho key: ${otpKey}`)

    try {
      // Lấy dữ liệu OTP từ Redis
      const otpData = await this.getOtpData(otpKey)

      // Kiểm tra số lần thử tối đa
      await this.checkOtpMaxAttempts(otpKey)

      // Kiểm tra thời gian hết hạn
      await this.checkOtpExpiry(otpKey, otpData.createdAt)

      // So sánh mã OTP
      if (otpData.code !== code) {
        this.logger.warn(`[verifyOTP] Mã OTP không chính xác cho key ${otpKey}`)
        // Ghi lại lần thử thất bại
        await this.redisService.hincrby(otpKey, 'attempts', 1)
        throw AuthError.InvalidOTP()
      }

      // Xóa OTP sau khi xác minh thành công
      await this.redisService.del(otpKey)
      this.logger.log(`[verifyOTP] OTP cho key ${otpKey} đã được xác minh thành công và đã xóa`)
      return true
    } catch (error) {
      if (error instanceof HttpException) throw error

      this.logger.error(`[verifyOTP] Lỗi xác minh OTP cho key ${otpKey}: ${error.message}`, error.stack)
      // Throw một lỗi chung để không tiết lộ chi tiết hệ thống
      throw AuthError.InvalidOTP()
    }
  }

  // ================================================================
  // Private Methods - OTP Data Management
  // ================================================================

  /**
   * Lấy dữ liệu OTP từ Redis và parse thành object
   * Xử lý deserialization của metadata và các trường số
   * @param otpKey - Redis key chứa OTP data
   * @returns Parsed OTP data object
   * @throws AuthError.OTPExpired nếu không tìm thấy data
   */
  private async getOtpData(otpKey: string): Promise<OtpData> {
    const rawOtpData = await this.redisService.hgetall(otpKey)
    if (!rawOtpData || Object.keys(rawOtpData).length === 0) {
      this.logger.warn(`[getOtpData] Không tìm thấy dữ liệu OTP cho key: ${otpKey}`)
      throw AuthError.OTPExpired()
    }

    // Parse rawOtpData thành OtpData structure
    const otpData: OtpData = {
      code: rawOtpData.code,
      attempts: parseInt(rawOtpData.attempts || '0', 10),
      createdAt: parseInt(rawOtpData.createdAt || '0', 10)
    }

    // Parse optional fields
    if (rawOtpData.userId) {
      otpData.userId = parseInt(rawOtpData.userId, 10)
    }

    if (rawOtpData.deviceId) {
      otpData.deviceId = parseInt(rawOtpData.deviceId, 10)
    }

    // Parse metadata JSON
    if (rawOtpData.metadata) {
      try {
        otpData.metadata = JSON.parse(rawOtpData.metadata)
      } catch (_e) {
        void _e
        this.logger.warn(`[getOtpData] Không thể parse OTP metadata: ${rawOtpData.metadata}`)
        otpData.metadata = { raw: rawOtpData.metadata }
      }
    }

    return otpData
  }

  // ================================================================
  // Private Methods - Validation & Security Checks
  // ================================================================

  /**
   * Kiểm tra số lần thử tối đa để ngăn chặn brute force attack
   * Tự động xóa OTP nếu vượt quá giới hạn
   * @param otpKey - Redis key chứa OTP data
   * @throws AuthError.TooManyOTPAttempts nếu vượt quá giới hạn
   */
  private async checkOtpMaxAttempts(otpKey: string): Promise<void> {
    const maxAttempts = this.configService.get<number>('OTP_MAX_ATTEMPTS', 5)
    const currentAttempts = parseInt((await this.redisService.hget(otpKey, 'attempts')) || '0', 10)

    if (currentAttempts >= maxAttempts) {
      this.logger.warn(`[checkOtpMaxAttempts] Vượt quá số lần thử tối đa cho key: ${otpKey}. Đang xóa OTP`)
      // Xóa OTP để ngăn chặn brute force attack
      await this.redisService.del(otpKey)
      throw AuthError.TooManyOTPAttempts()
    }
  }

  /**
   * Kiểm tra OTP có hết hạn hay không dựa trên timestamp
   * Tự động xóa OTP đã hết hạn khỏi Redis
   * @param otpKey - Redis key chứa OTP data
   * @param createdAtTimestamp - Timestamp khi OTP được tạo (milliseconds)
   * @throws AuthError.OTPExpired nếu OTP đã hết hạn
   */
  private async checkOtpExpiry(otpKey: string, createdAtTimestamp: number): Promise<void> {
    const otpExpirySeconds = this.configService.get<number>('OTP_EXPIRY_SECONDS', 300)

    if (Date.now() > createdAtTimestamp + otpExpirySeconds * 1000) {
      this.logger.warn(`[checkOtpExpiry] OTP đã hết hạn cho key: ${otpKey}. Đang xóa`)
      // Xóa OTP đã hết hạn khỏi Redis
      await this.redisService.del(otpKey)
      throw AuthError.OTPExpired()
    }
  }
}
