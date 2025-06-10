import { Injectable, Logger, Inject } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { I18nService, I18nContext } from 'nestjs-i18n'
import { JwtService } from '@nestjs/jwt'
import * as otplib from 'otplib'
import { HashAlgorithms } from '@otplib/core'
import {
  COOKIE_SERVICE,
  EMAIL_SERVICE,
  GEOLOCATION_SERVICE,
  HASHING_SERVICE,
  SLT_SERVICE,
  TOKEN_SERVICE,
  USER_AGENT_SERVICE
} from 'src/shared/constants/injection.tokens'
import { TypeOfVerificationCode, TwoFactorMethodType } from 'src/routes/auth/auth.constants'
import { RecoveryCodeRepository } from 'src/routes/auth/repositories'
import { DeviceRepository } from 'src/shared/repositories/device.repository'
import { HashingService } from 'src/shared/services/hashing.service'
import { RedisService } from 'src/shared/services/redis.service'
import { OtpService } from './otp.service'
import { ICookieService, ITokenService, IMultiFactorService } from 'src/routes/auth/auth.types'
import { AuthError } from '../auth.error'
import { SLTService } from 'src/shared/services/slt.service'
import { EmailService } from 'src/shared/services/email.service'
import { GeolocationService } from 'src/shared/services/geolocation.service'
import { UserAgentService } from 'src/shared/services/user-agent.service'
import { GlobalError } from 'src/shared/global.error'
import { I18nTranslations } from 'src/generated/i18n.generated'
import { UserRepository } from 'src/routes/user/user.repository'

/**
 * Cấu hình và hằng số
 */
const RECOVERY_CODES_COUNT = 8
const RECOVERY_CODE_LENGTH = 10
const TOTP_WINDOW = 2 // Cho phép mã hợp lệ trong khoảng thời gian 60 giây trước/sau

/**
 * Kết quả thiết lập TOTP
 */
interface TotpSetupResult {
  secret: string
  uri: string
}

/**
 * Service quản lý xác thực hai yếu tố (2FA)
 * Hỗ trợ các phương thức: TOTP (Google Authenticator), mã khôi phục
 */
@Injectable()
export class TwoFactorService implements IMultiFactorService {
  private readonly logger = new Logger(TwoFactorService.name)
  private readonly authenticator: typeof otplib.authenticator

  constructor(
    private readonly configService: ConfigService,
    private readonly i18nService: I18nService<I18nTranslations>,
    @Inject(COOKIE_SERVICE) private readonly cookieService: ICookieService,
    @Inject(TOKEN_SERVICE) private readonly tokenService: ITokenService,
    private readonly otpService: OtpService,
    @Inject(HASHING_SERVICE) private readonly hashingService: HashingService,
    private readonly userRepository: UserRepository,
    private readonly recoveryCodeRepository: RecoveryCodeRepository,
    private readonly deviceRepository: DeviceRepository,
    private readonly redisService: RedisService,
    private readonly jwtService: JwtService,
    @Inject(SLT_SERVICE) private readonly sltService: SLTService,
    @Inject(EMAIL_SERVICE) private readonly emailService: EmailService,
    @Inject(GEOLOCATION_SERVICE) private readonly geolocationService: GeolocationService,
    @Inject(USER_AGENT_SERVICE) private readonly userAgentService: UserAgentService
  ) {
    // Cấu hình authenticator
    this.authenticator = otplib.authenticator
    this.authenticator.options = {
      window: TOTP_WINDOW,
      step: 30, // 30 giây cho mỗi mã
      digits: 6,
      algorithm: HashAlgorithms.SHA1
    }
  }

  /**
   * PHẦN 1: THIẾT LẬP XÁC THỰC HAI YẾU TỐ
   */

  /**
   * Tạo thông tin cần thiết (secret, uri) để thiết lập TOTP.
   * Phương thức này không lưu bất cứ gì vào DB, chỉ tạo dữ liệu.
   */
  async generateSetupDetails(userId: number): Promise<{ message: string; data: { secret: string; qrCode: string } }> {
    this.logger.debug(`[generateSetupDetails] Generating 2FA setup details for userId ${userId}`)

    const user = await this.userRepository.findById(userId)

    if (!user) {
      this.logger.error(`[generateSetupDetails] User not found with ID: ${userId}`)
      throw GlobalError.NotFound('user')
    }

    if (user.twoFactorEnabled) {
      this.logger.warn(`[generateSetupDetails] User ${userId} already has 2FA enabled.`)
      throw AuthError.TOTPAlreadyEnabled()
    }

    const { secret, uri } = this.createTOTP(user.email)
    const qrCode = await this.generateQRCode(uri)

    return {
      message: this.i18nService.t('auth.success.2fa.setupInitiated'),
      data: {
        secret,
        qrCode
      }
    }
  }

  /**
   * Tạo và trả về mã xác thực cho TOTP
   * @implements IVerificationService.generateVerificationCode
   */
  async generateVerificationCode(options?: { secret: string }): Promise<string> {
    if (!options || !options.secret) {
      throw AuthError.InvalidTOTP()
    }

    return Promise.resolve(this.authenticator.generate(options.secret))
  }

  /**
   * Xác thực mã TOTP hoặc mã khôi phục
   * @implements IVerificationService.verifyCode
   */
  async verifyCode(
    code: string,
    context: {
      userId: number
      method?: string
      secret?: string
    }
  ): Promise<boolean> {
    this.logger.debug(
      `[verifyCode] Verifying 2FA code for userId: ${context.userId}, method: ${context.method || 'Not specified'}`
    )

    // Nếu context cung cấp secret trực tiếp (chỉ xảy ra trong quá trình thiết lập),
    // phương thức luôn là AUTHENTICATOR_APP.
    if (context.secret) {
      if (this.verifyTOTP(context.secret, code)) {
        return true
      }
      throw AuthError.InvalidTOTP()
    }

    // Xác định phương thức xác minh sẽ sử dụng
    const verificationMethod = context.method ?? TwoFactorMethodType.AUTHENTICATOR_APP

    // Xử lý dựa trên phương thức
    switch (verificationMethod as TwoFactorMethodType) {
      case TwoFactorMethodType.AUTHENTICATOR_APP: {
        const user = await this.userRepository.findById(context.userId)
        if (!user?.twoFactorEnabled || !user.twoFactorSecret) {
          throw AuthError.TOTPNotEnabled()
        }
        // Thử xác minh bằng TOTP trước
        if (this.verifyTOTP(user.twoFactorSecret, code)) {
          return true
        }
        // Nếu TOTP thất bại, thử mã khôi phục như một phương án dự phòng
        const isRecoveryCode = await this.verifyRecoveryCode(context.userId, code)
        if (isRecoveryCode) {
          return true
        }
        // Nếu cả hai đều thất bại
        throw AuthError.InvalidTOTP()
      }

      case TwoFactorMethodType.RECOVERY_CODE: {
        const isVerified = await this.verifyRecoveryCode(context.userId, code)
        if (!isVerified) {
          throw AuthError.InvalidRecoveryCode()
        }
        return true
      }

      default:
        this.logger.warn(`[verifyCode] Verification method '${verificationMethod}' not implemented.`)
        throw AuthError.InvalidVerificationMethod()
    }
  }

  /**
   * Vô hiệu hóa xác thực hai yếu tố sau khi xác thực
   * @implements IVerificationService.disableVerification
   */
  async disableVerification(userId: number, code: string, method?: string): Promise<{ message: string }> {
    this.logger.debug(`[disableVerification] Disabling 2FA for userId ${userId}`)

    // 1. Verify user with the provided code
    await this.verifyCode(code, { userId, method })

    // 2. Perform the actual disabling logic
    await this._performDisable(userId)

    // 3. Return success message
    return {
      message: this.i18nService.t('auth.success.2fa.disabled')
    }
  }

  /**
   * Disables two-factor authentication for a user after the verification code has already been confirmed.
   * This method does not perform any verification itself.
   * @param userId The ID of the user.
   * @returns A success message.
   */
  async disableVerificationAfterConfirm(userId: number): Promise<{ message: string }> {
    this.logger.debug(`[disableVerificationAfterConfirm] Disabling 2FA for userId ${userId} after pre-verification.`)
    await this._performDisable(userId)
    return {
      message: this.i18nService.t('auth.success.2fa.disabled')
    }
  }

  private async _performDisable(userId: number): Promise<void> {
    this.logger.debug(`[_performDisable] Performing 2FA disable logic for userId ${userId}`)
    // 1. Get user information
    const user = await this.userRepository.findByIdWithDetails(userId)
    if (!user) throw GlobalError.NotFound('user')

    // 2. Disable 2FA and delete recovery codes
    await this.userRepository.disableTwoFactor(userId)
    await this.recoveryCodeRepository.deleteRecoveryCodes(userId)

    // 3. Send notification email
    await this.emailService.sendTwoFactorStatusChangedEmail(user.email, {
      userName: user.userProfile?.username ?? user.email,
      action: 'disabled',
      details: []
    })
  }

  /**
   * Tạo mới các mã khôi phục.
   * Yêu cầu xác thực (đã thực hiện trước đó) để gọi hàm này.
   */
  async regenerateRecoveryCodes(
    userId: number,
    code: string,
    method?: string,
    ipAddress?: string,
    userAgent?: string
  ): Promise<{ message: string; data: { recoveryCodes: string[] } }> {
    this.logger.debug(`[regenerateRecoveryCodes] Regenerating recovery codes for user ${userId}`)

    // 1. Xác thực người dùng
    await this.verifyCode(code, { userId, method })

    // 2. Lấy thông tin người dùng
    const user = await this.userRepository.findByIdWithDetails(userId)
    if (!user) {
      this.logger.warn(`[regenerateRecoveryCodes] User not found: ${userId}`)
      throw GlobalError.NotFound('user')
    }

    if (!user.twoFactorEnabled) {
      this.logger.warn(`[regenerateRecoveryCodes] 2FA is not enabled for user ${userId}. Cannot regenerate codes.`)
      throw AuthError.TOTPNotEnabled()
    }

    const plainRecoveryCodes = this.generateRecoveryCodes()
    const hashedRecoveryCodes = await Promise.all(plainRecoveryCodes.map((code) => this.hashingService.hash(code)))

    await this.recoveryCodeRepository.tx(async (tx) => {
      await this.recoveryCodeRepository.deleteRecoveryCodes(userId, tx)
      await this.recoveryCodeRepository.createRecoveryCodes(userId, hashedRecoveryCodes, tx)
    })

    const i18nLang = I18nContext.current()?.lang
    const lang = i18nLang === 'en' ? 'en' : 'vi'
    const details = []
    if (ipAddress && userAgent) {
      const locationResult = await this.geolocationService.getLocationFromIP(ipAddress)
      const uaInfo = this.userAgentService.parse(userAgent)
      const localeForDate = lang === 'vi' ? 'vi-VN' : 'en-US'

      details.push(
        {
          label: this.i18nService.t('email.Email.common.details.time', { lang }),
          value: new Date().toLocaleString(localeForDate, {
            timeZone: locationResult.timezone || 'Asia/Ho_Chi_Minh',
            dateStyle: 'full',
            timeStyle: 'long'
          })
        },
        {
          label: this.i18nService.t('email.Email.common.details.ipAddress', { lang }),
          value: ipAddress
        },
        {
          label: this.i18nService.t('email.Email.common.details.device', { lang }),
          value: `${uaInfo.browser} on ${uaInfo.os}`
        }
      )
    }

    await this.emailService.sendRecoveryCodesEmail(user.email, {
      userName: user.userProfile?.username ?? user.email,
      recoveryCodes: plainRecoveryCodes,
      details,
      lang
    })

    this.logger.log(`[regenerateRecoveryCodes] Successfully regenerated recovery codes for user ${userId}.`)

    return {
      message: this.i18nService.t('auth.success.2fa.recoveryCodesRegenerated'),
      data: { recoveryCodes: plainRecoveryCodes }
    }
  }

  /**
   * Xác minh mã theo phương thức cụ thể
   * @implements IMultiFactorService.verifyByMethod
   */
  async verifyByMethod(
    method: string,
    code: string,
    userId: number
  ): Promise<{ message: string; data: { success: boolean; method: string } }> {
    this.logger.debug(`[verifyByMethod] Xác minh mã bằng phương thức: ${method}`)

    // Lấy thông tin người dùng
    const user = await this.userRepository.findById(userId)

    if (!user) {
      this.logger.error(`[verifyByMethod] Không tìm thấy người dùng với ID ${userId}`)
      throw GlobalError.NotFound('user')
    }

    // Xác minh theo phương thức cụ thể
    let success = false

    if (method === 'TOTP' && user.twoFactorSecret) {
      success = this.verifyTOTP(user.twoFactorSecret, code)
      if (success) {
        this.logger.debug(`[verifyByMethod] Xác minh TOTP thành công cho userId ${userId}`)
      }
    } else if (method === 'RECOVERY') {
      success = await this.verifyRecoveryCode(userId, code)
      if (success) {
        this.logger.debug(`[verifyByMethod] Xác minh mã khôi phục thành công cho userId ${userId}`)
      }
    } else {
      this.logger.error(`[verifyByMethod] Invalid verification method: ${method}`)
      throw AuthError.InvalidVerificationMethod()
    }

    if (success) {
      return {
        message: this.i18nService.t('auth.success.otp.verified'),
        data: { success, method }
      }
    }

    // Nếu không thành công, throw lỗi thay vì trả về success: false
    throw AuthError.InvalidOTP()
  }

  /**
   * PHẦN 2: CÁC HELPER METHOD
   */

  /**
   * Tạo TOTP instance với secret cho người dùng
   */
  private createTOTP(email: string, secret?: string): TotpSetupResult {
    // Tạo secret nếu chưa được cung cấp
    const finalSecret = secret || this.authenticator.generateSecret()

    // Tạo URI cho TOTP
    const uri = this.authenticator.keyuri(email, 'Shopsifu', finalSecret)

    return {
      secret: finalSecret,
      uri
    }
  }

  /**
   * Xác nhận thiết lập 2FA
   */
  async confirmTwoFactorSetup(
    userId: number,
    totpCode: string,
    secret: string,
    ipAddress?: string,
    userAgent?: string
  ): Promise<{ message: string; data: { recoveryCodes: string[] } }> {
    this.logger.debug(`[confirmTwoFactorSetup] Confirming 2FA setup for user ${userId}`)

    const user = await this.userRepository.findByIdWithDetails(userId)
    if (!user) throw GlobalError.NotFound('user')

    if (!this.verifyTOTP(secret, totpCode)) throw AuthError.InvalidTOTP()

    await this.userRepository.enableTwoFactor(userId, secret, TwoFactorMethodType.AUTHENTICATOR_APP)

    // This call now also sends an email with the codes
    const result = await this.regenerateRecoveryCodes(
      userId,
      totpCode, // Dùng lại totpCode để xác thực vì nó vẫn hợp lệ
      TwoFactorMethodType.AUTHENTICATOR_APP,
      ipAddress,
      userAgent
    )

    await this.emailService.sendTwoFactorStatusChangedEmail(user.email, {
      userName: user.userProfile?.username ?? user.email,
      action: 'enabled',
      details: []
    })

    return {
      message: this.i18nService.t('auth.success.2fa.setupConfirmed'),
      data: { recoveryCodes: result.data.recoveryCodes }
    }
  }

  /**
   * Tạo các mã khôi phục
   */
  private generateRecoveryCodes(count: number = RECOVERY_CODES_COUNT): string[] {
    const codes: string[] = []
    for (let i = 0; i < count; i++) {
      codes.push(this.generateRandomString(RECOVERY_CODE_LENGTH))
    }
    return codes
  }

  /**
   * Tạo chuỗi ngẫu nhiên với độ dài xác định
   */
  private generateRandomString(length: number): string {
    // Không sử dụng ký tự dễ gây nhầm lẫn
    const characters = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
    let result = ''
    const charactersLength = characters.length

    // Thêm dấu gạch ngang sau mỗi 5 ký tự
    for (let i = 0; i < length; i++) {
      if (i > 0 && i % 5 === 0) {
        result += '-'
      }
      result += characters.charAt(Math.floor(Math.random() * charactersLength))
    }

    return result
  }

  /**
   * Xác minh mã TOTP
   */
  private verifyTOTP(secret: string, token: string): boolean {
    try {
      const isValid = this.authenticator.verify({ token, secret })
      this.logger.debug(`[verifyTOTP] Kết quả xác minh TOTP: ${isValid}`)
      return isValid
    } catch (error) {
      this.logger.error(`[verifyTOTP] Lỗi khi xác minh TOTP: ${error.message}`, error.stack)
      return false
    }
  }

  /**
   * Xác minh mã khôi phục
   */
  private async verifyRecoveryCode(userId: number, code: string): Promise<boolean> {
    const recoveryCodes = await this.recoveryCodeRepository.findByUserId(userId)
    if (!recoveryCodes.length) return false

    for (const storedCode of recoveryCodes) {
      if (storedCode.used) continue
      const codeMatches = await this.hashingService.compare(code, storedCode.code)
      if (codeMatches) {
        await this.recoveryCodeRepository.markRecoveryCodeAsUsed(storedCode.id)
        return true
      }
    }
    return false
  }

  /**
   * PHẦN 5: HELPERS KHÁC
   */

  /**
   * Khởi tạo SLT cho một hành động 2FA
   */
  async initiateTwoFactorActionWithSltCookie(payload: {
    userId: number
    deviceId: number
    ipAddress: string
    userAgent: string
    purpose: TypeOfVerificationCode
    metadata?: Record<string, any>
  }): Promise<string> {
    this.logger.debug(
      `[initiateTwoFactorActionWithSltCookie] Khởi tạo SLT cho 2FA action. UserId: ${payload.userId}, Purpose: ${payload.purpose}`
    )

    return this.sltService.createAndStoreSltToken(payload)
  }

  /**
   * Lấy giá trị tin cậy hết hạn cho thiết bị
   */
  private getTrustExpirationDate(): Date {
    const trustDurationDays = this.configService.get<number>('security.deviceTrustDurationDays', 30)
    const expirationDate = new Date()
    expirationDate.setDate(expirationDate.getDate() + trustDurationDays)
    return expirationDate
  }

  private async generateQRCode(uri: string): Promise<string> {
    const QRCode = await import('qrcode')
    return QRCode.toDataURL(uri)
  }
}
