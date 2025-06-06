import { Injectable, Logger, Inject, forwardRef } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { I18nService } from 'nestjs-i18n'
import { JwtService } from '@nestjs/jwt'
import * as otplib from 'otplib'
import { HashAlgorithms } from '@otplib/core'
import {
  COOKIE_SERVICE,
  EMAIL_SERVICE,
  HASHING_SERVICE,
  REDIS_SERVICE,
  SLT_SERVICE,
  TOKEN_SERVICE
} from 'src/shared/constants/injection.tokens'
import { TypeOfVerificationCode, TwoFactorMethodType } from 'src/routes/auth/shared/constants/auth.constants'
import { UserAuthRepository, RecoveryCodeRepository, DeviceRepository } from 'src/routes/auth/shared/repositories'
import { HashingService } from 'src/routes/auth/shared/services/common/hashing.service'
import { RedisService } from 'src/providers/redis/redis.service'
import { OtpService } from '../otp/otp.service'
import { ICookieService, ITokenService, IMultiFactorService } from 'src/routes/auth/shared/auth.types'
import { AuthError } from '../../auth.error'
import { SLTService } from 'src/routes/auth/shared/services/slt.service'
import { EmailService } from 'src/routes/auth/shared/services/common/email.service'
import { CoreService } from '../core/core.service'
import { I18nTranslations } from 'src/generated/i18n.generated'

/**
 * Cấu hình và hằng số
 */
const RECOVERY_CODES_COUNT = 8
const RECOVERY_CODE_LENGTH = 10
const TOTP_WINDOW = 1 // Cho phép mã hợp lệ trong khoảng thời gian 30 giây trước/sau

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
    private readonly userAuthRepository: UserAuthRepository,
    private readonly recoveryCodeRepository: RecoveryCodeRepository,
    private readonly deviceRepository: DeviceRepository,
    @Inject(REDIS_SERVICE) private readonly redisService: RedisService,
    private readonly jwtService: JwtService,
    @Inject(SLT_SERVICE) private readonly sltService: SLTService,
    @Inject(EMAIL_SERVICE) private readonly emailService: EmailService,
    @Inject(forwardRef(() => CoreService))
    private readonly coreService: CoreService
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
  async generateSetupDetails(userId: number): Promise<TotpSetupResult> {
    this.logger.debug(`[generateSetupDetails] Generating 2FA setup details for userId ${userId}`)

    const user = await this.userAuthRepository.findById(userId, {
      email: true,
      twoFactorEnabled: true
    })

    if (!user) {
      this.logger.error(`[generateSetupDetails] User not found with ID: ${userId}`)
      throw AuthError.EmailNotFound()
    }

    if (user.twoFactorEnabled) {
      this.logger.warn(`[generateSetupDetails] User ${userId} already has 2FA enabled.`)
      throw AuthError.TOTPAlreadyEnabled()
    }

    return this.createTOTP(user.email)
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
    this.logger.debug(`[verifyCode] Verifying code for userId: ${context.userId}, method: ${context.method || 'TOTP'}`)

    if (!code) {
      throw AuthError.InvalidTOTP()
    }

    // Nếu context cung cấp secret trực tiếp (trường hợp thiết lập)
    if (context.secret) {
      const isValid = this.verifyTOTP(context.secret, code)
      if (!isValid) throw AuthError.InvalidTOTP()
      return true
    }

    // Lấy thông tin người dùng
    const user = await this.userAuthRepository.findById(context.userId, {
      twoFactorEnabled: true,
      twoFactorSecret: true
    })

    if (!user) {
      this.logger.error(`[verifyCode] User not found: ${context.userId}`)
      throw AuthError.EmailNotFound()
    }

    if (!user.twoFactorEnabled || !user.twoFactorSecret) {
      this.logger.warn(`[verifyCode] 2FA is not enabled for user: ${context.userId}`)
      throw AuthError.TOTPNotEnabled()
    }

    // Xác thực theo phương thức (TOTP hoặc mã khôi phục)
    const method = context.method || TwoFactorMethodType.TOTP
    const verificationResult = await this.verifyByMethod(method, code, context.userId)

    if (!verificationResult.success) {
      if (method === 'RECOVERY') {
        throw AuthError.InvalidRecoveryCode()
      }
      throw AuthError.InvalidTOTP()
    }
    return true
  }

  /**
   * Vô hiệu hóa xác thực hai yếu tố
   * @implements IVerificationService.disableVerification
   */
  async disableVerification(userId: number): Promise<void> {
    this.logger.debug(`[disableVerification] Vô hiệu hóa 2FA cho userId ${userId}`)

    // Vô hiệu hóa 2FA và xóa mã khôi phục (không yêu cầu xác minh)
    await this.userAuthRepository.disableTwoFactor(userId)
    await this.recoveryCodeRepository.deleteRecoveryCodes(userId)
  }

  /**
   * Tạo mới các mã khôi phục
   * @implements IMultiFactorService.regenerateRecoveryCodes
   */
  async regenerateRecoveryCodes(
    userId: number,
    verificationCode: string,
    options?: { ip?: string; userAgent?: string }
  ): Promise<string[]> {
    this.logger.debug(`[regenerateRecoveryCodes] Bắt đầu tạo lại mã khôi phục cho userId ${userId}`)

    // Lấy thông tin người dùng
    const user = await this.userAuthRepository.findById(userId, {
      twoFactorEnabled: true,
      twoFactorSecret: true,
      twoFactorMethod: true,
      email: true
    })

    if (!user) {
      this.logger.error(`[regenerateRecoveryCodes] Không tìm thấy người dùng với ID ${userId}`)
      throw AuthError.EmailNotFound()
    }

    if (!user.twoFactorEnabled || !user.twoFactorSecret) {
      this.logger.warn(`[regenerateRecoveryCodes] 2FA chưa được kích hoạt cho người dùng ${userId}`)
      throw AuthError.TOTPNotEnabled()
    }

    // Xác thực mã TOTP trước
    const isValid = this.verifyTOTP(user.twoFactorSecret, verificationCode)
    if (!isValid) {
      this.logger.warn(`[regenerateRecoveryCodes] Mã TOTP không hợp lệ cho userId ${userId}`)
      throw AuthError.InvalidTOTP()
    }

    // Tạo mã khôi phục mới
    const plainRecoveryCodes = this.generateRecoveryCodes()
    const hashedRecoveryCodes = await Promise.all(plainRecoveryCodes.map((code) => this.hashingService.hash(code)))

    // Xóa mã cũ và lưu mã mới
    await this.recoveryCodeRepository.deleteRecoveryCodes(userId)
    await this.recoveryCodeRepository.createRecoveryCodes(userId, hashedRecoveryCodes)

    return plainRecoveryCodes
  }

  /**
   * Xác minh mã theo phương thức cụ thể
   * @implements IMultiFactorService.verifyByMethod
   */
  async verifyByMethod(method: string, code: string, userId: number): Promise<{ success: boolean; method: string }> {
    this.logger.debug(`[verifyByMethod] Xác minh mã bằng phương thức: ${method}`)

    // Lấy thông tin người dùng
    const user = await this.userAuthRepository.findById(userId, {
      twoFactorEnabled: true,
      twoFactorSecret: true,
      twoFactorMethod: true
    })

    if (!user) {
      this.logger.error(`[verifyByMethod] Không tìm thấy người dùng với ID ${userId}`)
      throw AuthError.EmailNotFound()
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

    return { success, method }
  }

  /**
   * PHẦN 2: CÁC HELPER METHOD
   */

  /**
   * Tạo TOTP instance với secret cho người dùng
   */
  private createTOTP(email: string, secret?: string): TotpSetupResult {
    this.logger.debug(`[createTOTP] Đang tạo TOTP cho: ${email}`)

    // Tạo hoặc sử dụng secret đã có
    const secretKey = secret || this.authenticator.generateSecret()

    // Tạo URI cho QR code
    const appName = this.configService.get<string>('APP_NAME') || 'Shopsifu'
    const uri = this.authenticator.keyuri(email, appName, secretKey)

    return {
      secret: secretKey,
      uri
    }
  }

  /**
   * Xác nhận thiết lập 2FA
   */
  async confirmTwoFactorSetup(
    userId: number,
    totpCode: string,
    secret: string
  ): Promise<{ message: string; recoveryCodes: string[] }> {
    this.logger.debug(`[confirmTwoFactorSetup] Bắt đầu xác nhận thiết lập 2FA cho userId ${userId}`)

    // Xác thực TOTP code
    const isValid = await this.verifyCode(totpCode, { userId, secret })
    if (!isValid) {
      this.logger.warn(`[confirmTwoFactorSetup] Mã xác thực không đúng cho userId ${userId}`)
      throw AuthError.InvalidTOTP()
    }

    // Tạo mã khôi phục
    const plainRecoveryCodes = this.generateRecoveryCodes()
    const hashedRecoveryCodes = await Promise.all(plainRecoveryCodes.map((code) => this.hashingService.hash(code)))

    // Cập nhật thông tin người dùng và lưu mã khôi phục trong transaction
    try {
      await this.userAuthRepository.enableTwoFactor(userId, secret, TwoFactorMethodType.TOTP)
      await this.recoveryCodeRepository.createRecoveryCodes(userId, hashedRecoveryCodes)

      this.logger.debug(`[confirmTwoFactorSetup] 2FA đã được kích hoạt thành công cho userId ${userId}`)

      return {
        message: this.i18nService.t('auth.Auth.2FA.Confirm.Success'),
        recoveryCodes: plainRecoveryCodes
      }
    } catch (error) {
      this.logger.error(
        `[confirmTwoFactorSetup] Lỗi khi thiết lập 2FA cho userId ${userId}: ${error.message}`,
        error.stack
      )
      throw AuthError.InternalServerError(error.message)
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
    try {
      // Lấy tất cả các mã khôi phục chưa sử dụng của người dùng
      const recoveryCodes = await this.recoveryCodeRepository.findUnusedRecoveryCodesByUserId(userId)
      if (!recoveryCodes || recoveryCodes.length === 0) {
        this.logger.warn(`[verifyRecoveryCode] Không tìm thấy mã khôi phục cho userId ${userId}`)
        return false
      }

      // Kiểm tra từng mã khôi phục
      for (const recoveryCode of recoveryCodes) {
        const isMatch = await this.hashingService.compare(code, recoveryCode.code)
        if (isMatch) {
          // Đánh dấu mã khôi phục đã sử dụng
          await this.recoveryCodeRepository.markRecoveryCodeAsUsed(recoveryCode.id)
          return true
        }
      }

      this.logger.warn(`[verifyRecoveryCode] Mã khôi phục không hợp lệ cho userId ${userId}`)
      return false
    } catch (error) {
      this.logger.error(`[verifyRecoveryCode] Lỗi khi xác minh mã khôi phục: ${error.message}`, error.stack)
      return false
    }
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
}
