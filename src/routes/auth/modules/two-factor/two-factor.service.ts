import { Injectable, Logger, Inject, UnauthorizedException, BadRequestException, HttpStatus } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { I18nService } from 'nestjs-i18n'
import { JwtService } from '@nestjs/jwt'
import * as otplib from 'otplib'
import { HashAlgorithms } from '@otplib/core'
import * as crypto from 'crypto'
import { Response } from 'express'
import { COOKIE_SERVICE, REDIS_SERVICE, SLT_SERVICE, TOKEN_SERVICE } from 'src/shared/constants/injection.tokens'
import { TypeOfVerificationCode, TwoFactorMethodType } from 'src/shared/constants/auth.constants'
import { UserAuthRepository } from 'src/shared/repositories/auth/user-auth.repository'
import { HashingService } from 'src/shared/services/hashing.service'
import { RecoveryCodeRepository } from 'src/shared/repositories/auth/recovery-code.repository'
import { RedisService } from 'src/shared/providers/redis/redis.service'
import { OtpService } from '../otp/otp.service'
import { DeviceRepository } from 'src/shared/repositories/auth/device.repository'
import { ICookieService, ITokenService, IMultiFactorService } from 'src/shared/types/auth.types'
import { SltContextData } from '../../auth.types'
import { AuthError } from '../../auth.error'
import { RedisKeyManager } from 'src/shared/utils/redis-keys.utils'
import { PickedUserProfileResponseType } from 'src/shared/dtos/user.dto'
import { SLTService } from 'src/shared/services/auth/slt.service'

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
    private readonly i18nService: I18nService,
    @Inject(COOKIE_SERVICE) private readonly cookieService: ICookieService,
    @Inject(TOKEN_SERVICE) private readonly tokenService: ITokenService,
    private readonly otpService: OtpService,
    private readonly hashingService: HashingService,
    private readonly userAuthRepository: UserAuthRepository,
    private readonly recoveryCodeRepository: RecoveryCodeRepository,
    private readonly deviceRepository: DeviceRepository,
    @Inject(REDIS_SERVICE) private readonly redisService: RedisService,
    private readonly jwtService: JwtService,
    @Inject(SLT_SERVICE) private readonly sltService: SLTService
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
   * Thiết lập xác thực hai yếu tố cho người dùng
   * @implements IVerificationService.setupVerification
   */
  async setupVerification(
    userId: number,
    options?: {
      deviceId: number
      ip: string
      userAgent: string
      res: Response
    }
  ): Promise<TotpSetupResult> {
    this.logger.debug(`[setupVerification] Bắt đầu thiết lập 2FA cho userId ${userId}`)

    if (!options) {
      throw new BadRequestException('Thiếu thông tin thiết bị')
    }

    const { deviceId, ip, userAgent, res } = options

    // Kiểm tra người dùng đã bật 2FA chưa
    const user = await this.userAuthRepository.findById(userId, {
      email: true,
      twoFactorEnabled: true
    })

    if (!user) {
      this.logger.error(`[setupVerification] Không tìm thấy người dùng với ID ${userId}`)
      throw AuthError.EmailNotFound()
    }

    if (user.twoFactorEnabled) {
      this.logger.warn(`[setupVerification] Người dùng ${userId} đã bật 2FA trước đó`)
      throw AuthError.TOTPAlreadyEnabled()
    }

    // Tạo secret và URI
    const { secret, uri } = this.createTOTP(user.email)

    // Tạo SLT để lưu trữ secret tạm thời trong quá trình thiết lập
    const sltToken = await this.sltService.createAndStoreSltToken({
      userId,
      deviceId,
      ipAddress: ip,
      userAgent,
      purpose: TypeOfVerificationCode.SETUP_2FA,
      metadata: {
        secret,
        twoFactorMethod: TwoFactorMethodType.TOTP
      }
    })

    // Đặt SLT cookie
    this.cookieService.setSltCookie(res, sltToken, TypeOfVerificationCode.SETUP_2FA)

    return { secret, uri }
  }

  /**
   * Tạo và trả về mã xác thực cho TOTP
   * @implements IVerificationService.generateVerificationCode
   */
  async generateVerificationCode(options?: { secret: string }): Promise<string> {
    if (!options || !options.secret) {
      throw new BadRequestException('Secret không được cung cấp')
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
      `[verifyCode] Xác thực mã cho userId: ${context.userId}, phương thức: ${context.method || 'TOTP'}`
    )

    if (!code) {
      throw AuthError.InvalidTOTP()
    }

    // Nếu context cung cấp secret trực tiếp (trường hợp thiết lập)
    if (context.secret) {
      return this.verifyTOTP(context.secret, code)
    }

    // Lấy thông tin người dùng
    const user = await this.userAuthRepository.findById(context.userId, {
      twoFactorEnabled: true,
      twoFactorSecret: true
    })

    if (!user) {
      this.logger.error(`[verifyCode] Không tìm thấy người dùng ${context.userId}`)
      throw AuthError.EmailNotFound()
    }

    if (!user.twoFactorEnabled || !user.twoFactorSecret) {
      this.logger.warn(`[verifyCode] 2FA chưa được kích hoạt cho người dùng ${context.userId}`)
      throw AuthError.TOTPNotEnabled()
    }

    // Xác thực theo phương thức (TOTP hoặc mã khôi phục)
    const method = context.method || TwoFactorMethodType.TOTP
    const result = await this.verifyByMethod(method, code, context.userId)
    return result.success
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
      this.logger.error(`[verifyByMethod] Phương thức xác thực không hợp lệ: ${method}`)
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
    sltCookieValue: string,
    totpCode: string,
    ip: string,
    userAgent: string,
    res: Response
  ): Promise<{ message: string; recoveryCodes: string[] }> {
    this.logger.debug(`[confirmTwoFactorSetup] Bắt đầu xác nhận thiết lập 2FA cho userId ${userId}`)

    // Xác thực SLT token
    const sltContext = await this.sltService.validateSltFromCookieAndGetContext(
      sltCookieValue,
      ip,
      userAgent,
      TypeOfVerificationCode.SETUP_2FA
    )

    if (sltContext.userId !== userId) {
      this.logger.warn(
        `[confirmTwoFactorSetup] Không trùng khớp userId. Expected: ${userId}, Got: ${sltContext.userId}`
      )
      throw AuthError.SLTInvalidPurpose()
    }

    const secret = sltContext.metadata?.secret
    if (!secret) {
      this.logger.error('[confirmTwoFactorSetup] Không tìm thấy secret trong metadata của SLT')
      throw new BadRequestException('Secret không được tìm thấy trong quá trình thiết lập')
    }

    // Xác thực TOTP code
    const isValid = await this.verifyCode(totpCode, { userId, secret })
    if (!isValid) {
      this.logger.warn(`[confirmTwoFactorSetup] Mã xác thực không đúng cho userId ${userId}`)
      await this.sltService.incrementSltAttempts(sltContext.sltJti)
      throw AuthError.InvalidTOTP()
    }

    // Tạo mã khôi phục
    const plainRecoveryCodes = this.generateRecoveryCodes()
    const hashedRecoveryCodes = await Promise.all(plainRecoveryCodes.map((code) => this.hashingService.hash(code)))

    // Cập nhật thông tin người dùng và lưu mã khôi phục trong transaction
    try {
      await this.userAuthRepository.enableTwoFactor(userId, secret, TwoFactorMethodType.TOTP)
      await this.recoveryCodeRepository.createRecoveryCodes(userId, hashedRecoveryCodes)

      // Đánh dấu SLT token đã được sử dụng
      await this.sltService.finalizeSlt(sltContext.sltJti)
      this.cookieService.clearSltCookie(res)

      this.logger.debug(`[confirmTwoFactorSetup] 2FA đã được kích hoạt thành công cho userId ${userId}`)

      return {
        message: this.i18nService.t('Auth.Auth.TwoFactor.EnableSuccess'),
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
   * PHẦN 3: XÁC MINH 2FA TRONG LUỒNG ĐĂNG NHẬP
   */

  /**
   * Xác minh 2FA trong quá trình đăng nhập
   */
  async verifyTwoFactor(
    code: string,
    rememberMe: boolean,
    sltCookieValue: string,
    ip: string,
    userAgent: string,
    method: string = TwoFactorMethodType.TOTP
  ): Promise<{
    message: string
    requiresDeviceVerification?: boolean
    verifiedMethod: string
    user?: {
      id: number
      email: string
      roleName: string
      isDeviceTrustedInSession: boolean
      userProfile: PickedUserProfileResponseType | null
    }
    purpose?: TypeOfVerificationCode
    userId?: number
    sltDeviceId?: number
    metadata?: any
  }> {
    this.logger.debug(`[verifyTwoFactor] Bắt đầu xác minh 2FA cho method: ${method}`)

    // Xác thực SLT token mà không yêu cầu purpose cụ thể
    const sltContext = await this.sltService.validateSltFromCookieAndGetContext(sltCookieValue, ip, userAgent)

    const userId = sltContext.userId

    // Lấy thông tin người dùng
    const user = await this.userAuthRepository.findById(userId, {
      email: true,
      twoFactorEnabled: true,
      twoFactorSecret: true,
      role: true
    })

    if (!user) {
      this.logger.error(`[verifyTwoFactor] Không tìm thấy người dùng ${userId}`)
      throw AuthError.EmailNotFound()
    }

    if (!user.twoFactorEnabled || !user.twoFactorSecret) {
      this.logger.warn(`[verifyTwoFactor] 2FA chưa được kích hoạt cho người dùng ${userId}`)
      throw AuthError.TOTPNotEnabled()
    }

    // Xác thực mã theo phương thức đã chọn
    const verificationResult = await this.verifyByMethod(method, code, userId)

    // Tăng số lần thử nếu xác minh thất bại
    if (!verificationResult.success) {
      await this.sltService.incrementSltAttempts(sltContext.sltJti)
      throw AuthError.InvalidTOTP()
    }

    // Đánh dấu SLT đã được sử dụng thành công
    await this.sltService.finalizeSlt(sltContext.sltJti)

    // Xử lý kết quả xác minh thành công
    return this.handleSuccessfulVerification(sltContext, user, verificationResult.method, rememberMe)
  }

  /**
   * Xử lý sau khi xác minh 2FA thành công
   */
  private async handleSuccessfulVerification(
    sltContext: SltContextData & { sltJti: string },
    user: any,
    verifiedMethod: string,
    rememberMe: boolean
  ) {
    this.logger.debug(`[handleSuccessfulVerification] Xác minh 2FA thành công cho userId ${user.id}`)

    // Xử lý các trường hợp khác nhau dựa trên purpose của SLT
    switch (sltContext.purpose) {
      case TypeOfVerificationCode.LOGIN_UNTRUSTED_DEVICE_2FA:
        // Đăng nhập trên thiết bị chưa tin cậy
        return {
          message: this.i18nService.t('Auth.Auth.TwoFactor.VerificationSuccess'),
          verifiedMethod,
          user: {
            id: user.id,
            email: user.email,
            roleName: user.role.name,
            isDeviceTrustedInSession: false,
            userProfile: user.userProfile
          },
          purpose: sltContext.purpose,
          userId: user.id,
          sltDeviceId: sltContext.deviceId,
          metadata: {
            ...(sltContext.metadata || {}),
            rememberMe
          }
        }
      case TypeOfVerificationCode.DISABLE_2FA:
        // Vô hiệu hóa 2FA
        await this.disableVerification(user.id)
        return {
          message: this.i18nService.t('Auth.Auth.TwoFactor.DisableSuccess'),
          verifiedMethod
        }
      case TypeOfVerificationCode.REVOKE_SESSIONS_2FA:
      case TypeOfVerificationCode.REVOKE_ALL_SESSIONS_2FA:
        // Thu hồi phiên
        return {
          message: this.i18nService.t('Auth.Auth.TwoFactor.VerificationSuccess'),
          verifiedMethod,
          metadata: sltContext.metadata
        }
      default:
        // Trường hợp mặc định
        return {
          message: this.i18nService.t('Auth.Auth.TwoFactor.VerificationSuccess'),
          verifiedMethod
        }
    }
  }

  /**
   * PHẦN 4: VÔ HIỆU HÓA 2FA
   */

  /**
   * Vô hiệu hóa 2FA với xác minh (TOTP, RECOVERY hoặc mật khẩu)
   */
  async disableTwoFactorWithVerification(
    userId: number,
    code: string,
    method?: 'TOTP' | 'RECOVERY' | 'PASSWORD',
    ip?: string,
    userAgent?: string,
    sltCookieValue?: string
  ): Promise<{ message: string }> {
    this.logger.debug(
      `[disableTwoFactorWithVerification] Bắt đầu vô hiệu hóa 2FA cho userId ${userId} với phương thức ${method}`
    )

    // Lấy thông tin người dùng
    const user = await this.userAuthRepository.findById(userId, {
      twoFactorEnabled: true,
      twoFactorSecret: true,
      twoFactorMethod: true,
      email: true
    })

    if (!user) {
      this.logger.error(`[disableTwoFactorWithVerification] Không tìm thấy người dùng ${userId}`)
      throw AuthError.EmailNotFound()
    }

    if (!user.twoFactorEnabled) {
      this.logger.warn(`[disableTwoFactorWithVerification] 2FA đã bị vô hiệu hóa cho userId ${userId}`)
      return { message: this.i18nService.t('Auth.Auth.TwoFactor.AlreadyDisabled') }
    }

    // Nếu có SLT cookie, xác thực nó
    if (sltCookieValue && ip && userAgent) {
      await this.validateAndFinalizeSltForDisable(sltCookieValue, ip, userAgent, userId)
    }

    // Xác thực mã theo phương thức
    if (method && code) {
      await this.verifyCodeForDisable(userId, code, method, user)
    } else {
      throw AuthError.InvalidVerificationMethod()
    }

    // Vô hiệu hóa 2FA
    await this.disableVerification(userId)

    return { message: this.i18nService.t('Auth.Auth.TwoFactor.DisableSuccess') }
  }

  /**
   * Xác thực SLT cho vô hiệu hóa 2FA
   */
  private async validateAndFinalizeSltForDisable(
    sltCookieValue: string,
    ip: string,
    userAgent: string,
    userId: number
  ): Promise<void> {
    const sltContext = await this.sltService.validateSltFromCookieAndGetContext(
      sltCookieValue,
      ip,
      userAgent,
      TypeOfVerificationCode.DISABLE_2FA
    )

    if (sltContext.userId !== userId) {
      this.logger.warn(
        `[validateAndFinalizeSltForDisable] Không trùng khớp userId. Expected: ${userId}, Got: ${sltContext.userId}`
      )
      throw AuthError.SLTInvalidPurpose()
    }

    await this.sltService.finalizeSlt(sltContext.sltJti)
  }

  /**
   * Xác thực mã cho vô hiệu hóa 2FA
   */
  private async verifyCodeForDisable(userId: number, code: string, method: string, user: any): Promise<void> {
    if (method === 'TOTP' && user.twoFactorSecret) {
      const isValid = this.verifyTOTP(user.twoFactorSecret, code)
      if (!isValid) {
        this.logger.warn(`[verifyCodeForDisable] Mã TOTP không hợp lệ cho userId ${userId}`)
        throw AuthError.InvalidTOTP()
      }
    } else if (method === 'RECOVERY') {
      const isValid = await this.verifyRecoveryCode(userId, code)
      if (!isValid) {
        this.logger.warn(`[verifyCodeForDisable] Mã khôi phục không hợp lệ cho userId ${userId}`)
        throw AuthError.InvalidRecoveryCode()
      }
    } else if (method === 'PASSWORD') {
      // Xác thực mật khẩu được xử lý ở controller/service khác trước khi gọi hàm này
      this.logger.debug(`[verifyCodeForDisable] Mật khẩu đã được xác thực trước đó`)
    } else {
      this.logger.error(`[verifyCodeForDisable] Phương thức không hợp lệ: ${method}`)
      throw AuthError.InvalidVerificationMethod()
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
