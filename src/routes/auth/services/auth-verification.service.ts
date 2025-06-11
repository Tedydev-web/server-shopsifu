// ================================================================
// NestJS Dependencies
// ================================================================
import { Injectable, Logger, Inject, forwardRef } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { I18nService } from 'nestjs-i18n'

// ================================================================
// External Libraries
// ================================================================
import { Response } from 'express'
import { TwoFactorMethodType, User } from '@prisma/client'

// ================================================================
// Internal Services & Types
// ================================================================
import { RedisService } from '../../../shared/providers/redis/redis.service'
import { SLTService } from '../../../shared/services/slt.service'
import { EmailService } from '../../../shared/services/email.service'
import { GeolocationService } from '../../../shared/services/geolocation.service'
import { UserAgentService } from '../../../shared/services/user-agent.service'

// ================================================================
// Auth Services
// ================================================================
import { TwoFactorService } from './two-factor.service'
import { SessionsService } from './session.service'
import { SocialService } from './social.service'
import { PasswordService } from './password.service'

// ================================================================
// Repositories
// ================================================================
import { DeviceRepository } from 'src/shared/repositories/device.repository'
import { UserRepository } from 'src/routes/user/user.repository'

// ================================================================
// Constants & Injection Tokens
// ================================================================
import {
  COOKIE_SERVICE,
  SLT_SERVICE,
  OTP_SERVICE,
  TWO_FACTOR_SERVICE,
  EMAIL_SERVICE,
  GEOLOCATION_SERVICE,
  USER_AGENT_SERVICE
} from '../../../shared/constants/injection.tokens'
import { TypeOfVerificationCode, TypeOfVerificationCodeType } from '../auth.constants'

// ================================================================
// Types & Interfaces
// ================================================================
import {
  ICookieService,
  SltContextData,
  IOTPService,
  ILoginFinalizationPayload,
  ILoginFinalizerService,
  LOGIN_FINALIZER_SERVICE
} from '../auth.types'
import { I18nTranslations } from 'src/generated/i18n.generated'
import { AuthError } from '../auth.error'
import { ApiException } from '../../../shared/exceptions/api.exception'
import { GlobalError } from 'src/shared/global.error'

/**
 * Service quản lý quy trình xác thực người dùng
 * - Xử lý login với nhiều bước xác thực (2FA, OTP, device verification)
 * - Quản lý security level tokens (SLT) cho các thao tác nhạy cảm
 * - Tích hợp với social login và password-based authentication
 * - Hỗ trợ nhiều phương thức 2FA và device trust management
 */

/**
 * Context thông tin cần thiết cho quá trình xác thực
 */
export interface VerificationContext {
  /** ID của user thực hiện xác thực */
  userId: number
  /** ID của thiết bị đang sử dụng */
  deviceId: number
  /** Email của user */
  email: string
  /** Địa chỉ IP hiện tại */
  ipAddress: string
  /** User agent của browser */
  userAgent: string
  /** Loại xác thực cần thực hiện */
  purpose: TypeOfVerificationCodeType
  /** Metadata bổ sung cho xác thực */
  metadata?: Record<string, any>
  /** Có ghi nhớ đăng nhập hay không */
  rememberMe?: boolean
}

/**
 * Kết quả trả về sau khi xác thực
 */
export interface VerificationResult {
  /** Thông báo kết quả */
  message: string
  /** Dữ liệu bổ sung */
  data?: Record<string, any>
}

/**
 * Handler xử lý logic sau khi xác thực thành công
 */
type PostVerificationHandler = (
  context: SltContextData & { sltJti: string },
  code: string,
  res: Response,
  sltCookieValue?: string
) => Promise<VerificationResult>

/**
 * Service xử lý tất cả các luồng xác thực (OTP/2FA) trong hệ thống
 *
 * Chức năng chính:
 * - Khởi tạo luồng xác thực cho đăng nhập và các hành động nhạy cảm
 * - Xác minh mã OTP/2FA từ user
 * - Xử lý logic nghiệp vụ sau khi xác thực thành công
 * - Quản lý SLT (Short-Lived Token) trong toàn bộ quá trình
 */
@Injectable()
export class AuthVerificationService {
  private readonly logger = new Logger(AuthVerificationService.name)

  /** Danh sách các hành động nhạy cảm luôn yêu cầu xác thực bảo mật cao */
  private readonly SENSITIVE_PURPOSES: TypeOfVerificationCodeType[] = [
    TypeOfVerificationCode.DISABLE_2FA,
    TypeOfVerificationCode.REVOKE_SESSIONS,
    TypeOfVerificationCode.REVOKE_ALL_SESSIONS,
    TypeOfVerificationCode.UNLINK_GOOGLE_ACCOUNT,
    TypeOfVerificationCode.REGENERATE_2FA_CODES,
    TypeOfVerificationCode.RESET_PASSWORD,
    TypeOfVerificationCode.CHANGE_PASSWORD
  ]

  /** Map handlers xử lý nghiệp vụ sau khi xác thực thành công */
  private readonly VERIFICATION_ACTION_HANDLERS: Partial<Record<TypeOfVerificationCodeType, PostVerificationHandler>>

  constructor(
    private readonly configService: ConfigService,
    private readonly redisService: RedisService,
    @Inject(COOKIE_SERVICE) private readonly cookieService: ICookieService,
    @Inject(SLT_SERVICE) private readonly sltService: SLTService,
    @Inject(OTP_SERVICE) private readonly otpService: IOTPService,
    @Inject(TWO_FACTOR_SERVICE) private readonly twoFactorService: TwoFactorService,
    private readonly userRepository: UserRepository,
    private readonly deviceRepository: DeviceRepository,
    private readonly i18nService: I18nService<I18nTranslations>,
    @Inject(LOGIN_FINALIZER_SERVICE) private readonly loginFinalizerService: ILoginFinalizerService,
    @Inject(forwardRef(() => SessionsService)) private readonly sessionsService: SessionsService,
    @Inject(forwardRef(() => SocialService)) private readonly socialService: SocialService,
    @Inject(EMAIL_SERVICE) private readonly emailService: EmailService,
    @Inject(GEOLOCATION_SERVICE) private readonly geolocationService: GeolocationService,
    @Inject(USER_AGENT_SERVICE) private readonly userAgentService: UserAgentService,
    private readonly passwordService: PasswordService
  ) {
    this.VERIFICATION_ACTION_HANDLERS = this.initializeActionHandlers()
  }

  // ================================================================
  // Service Initialization
  // ================================================================

  /**
   * Khởi tạo map handlers xử lý các hành động sau khi xác thực thành công
   * Tách riêng để code dễ đọc và maintain hơn
   * @returns Map các handlers được bind với context phù hợp
   */
  private initializeActionHandlers(): Partial<Record<TypeOfVerificationCodeType, PostVerificationHandler>> {
    return {
      [TypeOfVerificationCode.LOGIN]: (context, _code, res) => {
        const { userId, deviceId, ipAddress, userAgent, metadata } = context
        const rememberMe = metadata?.rememberMe === true
        return this.handleLoginVerification(userId, deviceId, rememberMe, ipAddress, userAgent, res)
      },
      [TypeOfVerificationCode.REVOKE_SESSIONS]: this.handleRevokeSessionsVerification.bind(this),
      [TypeOfVerificationCode.REVOKE_ALL_SESSIONS]: this.handleRevokeAllSessionsVerification.bind(this),
      [TypeOfVerificationCode.UNLINK_GOOGLE_ACCOUNT]: this.handleUnlinkGoogleAccountVerification.bind(this),
      [TypeOfVerificationCode.DISABLE_2FA]: this.handleDisable2FAVerification.bind(this),
      [TypeOfVerificationCode.SETUP_2FA]: this.handleSetup2FAVerification.bind(this),
      [TypeOfVerificationCode.REGISTER]: this.handleRegistrationOtpVerified.bind(this),
      [TypeOfVerificationCode.REGENERATE_2FA_CODES]: this.handleRegenerate2FACodesVerification.bind(this),
      [TypeOfVerificationCode.RESET_PASSWORD]: this.handleResetPasswordVerification.bind(this),
      [TypeOfVerificationCode.CHANGE_PASSWORD]: this.handleChangePasswordVerification.bind(this)
    }
  }

  // ================================================================
  // Public Methods - Main Verification Flow
  // ================================================================

  /**
   * Entry point chính cho tất cả các luồng xác thực trong hệ thống
   *
   * Phân tích context và quyết định có cần xác thực hay không.
   * Khởi tạo OTP/2FA nếu cần thiết và quản lý SLT cookie.
   *
   * @param context - Context chứa thông tin user, device, purpose
   * @param res - Response object để set SLT cookie
   * @returns Kết quả khởi tạo: đăng nhập thành công hoặc yêu cầu xác thực
   */
  async initiateVerification(context: VerificationContext, res: Response): Promise<VerificationResult> {
    const { userId, purpose } = context
    this.logger.debug(`[initiateVerification] UserID: ${userId}, Purpose: ${purpose}`)

    // Xử lý đặc biệt cho đăng ký - không cần check user tồn tại
    if (purpose === TypeOfVerificationCode.REGISTER) {
      return this.handleRegistrationInitiation(context, res)
    }

    // Xử lý thiết lập 2FA - tạo QR code và secret
    if (purpose === TypeOfVerificationCode.SETUP_2FA) {
      this.logger.debug(`[initiateVerification] Starting 2FA setup flow. Creating SLT.`)
      const sltToken = await this.sltService.createAndStoreSltToken(context)
      this.cookieService.setSltCookie(res, sltToken, purpose)
      const result = await this.twoFactorService.generateSetupDetails(context.userId)

      // Lưu secret vào SLT context để verify ở bước tiếp theo
      await this.sltService.updateSltContext(sltToken, {
        metadata: { ...context.metadata, twoFactorSecret: result.data.secret }
      })

      return {
        message: 'auth.success.2fa.setupInitiated',
        data: {
          qrCode: result.data.qrCode,
          secret: result.data.secret // Chỉ trả về ở dev environment
        }
      }
    }

    // Validate user tồn tại cho các purpose khác (trừ register)
    const user = await this.userRepository.findById(userId)
    if (!user) {
      throw AuthError.EmailNotFound()
    }

    // Xử lý đăng nhập hoặc các hành động nhạy cảm cần security cao
    if (this.SENSITIVE_PURPOSES.includes(purpose) || purpose === TypeOfVerificationCode.LOGIN) {
      return this.handleLoginOrSensitiveActionInitiation(context, res, user)
    }

    this.logger.warn(`[initiateVerification] No defined action for purpose: ${purpose}.`)
    return {
      message: 'global.general.success.default'
    }
  }

  /**
   * Xử lý khởi tạo luồng đăng ký - gửi OTP qua email
   */
  private handleRegistrationInitiation(context: VerificationContext, res: Response): Promise<VerificationResult> {
    this.logger.debug(`[handleRegistrationInitiation] Initiating registration flow for email ${context.email}`)
    return this.initiateOtpFlow(context, res)
  }

  /**
   * Xử lý đăng nhập hoặc các hành động nhạy cảm cần bảo mật cao
   *
   * Quyết định có cần xác thực bổ sung hay không dựa trên:
   * - Tính nhạy cảm của hành động
   * - Trạng thái trusted của thiết bị
   * - Có force verification hay không
   */
  private async handleLoginOrSensitiveActionInitiation(
    context: VerificationContext,
    res: Response,
    user: User
  ): Promise<VerificationResult> {
    const { purpose } = context

    // Tất cả hành động nhạy cảm đều yêu cầu xác thực
    if (this.SENSITIVE_PURPOSES.includes(purpose)) {
      this.logger.debug(`[handleLoginOrSensitiveAction] Sensitive action (${purpose}) requires verification.`)
      return this.initiateOtpOr2faFlow(context, res, user)
    }

    // Xử lý đặc biệt cho đăng nhập
    if (purpose === TypeOfVerificationCode.LOGIN) {
      return this.handleLoginSpecificLogic(context, res, user)
    }

    this.logger.warn(`[handleLoginOrSensitiveAction] No defined action for purpose: ${purpose}.`)
    return { message: 'global.general.success.default' }
  }

  /**
   * Xử lý logic riêng cho đăng nhập - kiểm tra trusted device
   */
  private async handleLoginSpecificLogic(
    context: VerificationContext,
    res: Response,
    user: User
  ): Promise<VerificationResult> {
    const { userId, deviceId, metadata, ipAddress, userAgent, rememberMe } = context
    const isDeviceTrusted = await this.deviceRepository.isDeviceTrustValid(deviceId)
    const forceVerification = metadata?.forceVerification === true

    // Yêu cầu xác thực nếu: force verification HOẶC thiết bị chưa trusted
    if (forceVerification || !isDeviceTrusted) {
      this.logger.log(
        `[handleLoginSpecificLogic] Verification required for UserID: ${user.id}. Force: ${forceVerification}, Trusted: ${isDeviceTrusted}`
      )
      return this.initiateOtpOr2faFlow(context, res, user)
    }

    // Thiết bị trusted - cho phép đăng nhập trực tiếp
    this.logger.debug(`[handleLoginSpecificLogic] Trusted device login for UserID: ${user.id}. Skipping OTP/2FA.`)
    return this.handleLoginVerification(userId, deviceId, rememberMe ?? false, ipAddress, userAgent, res)
  }

  /**
   * Khởi tạo luồng OTP hoặc 2FA dựa trên cài đặt của user
   *
   * Ưu tiên 2FA nếu user đã enable, ngược lại dùng OTP qua email
   */
  private async initiateOtpOr2faFlow(
    context: VerificationContext,
    res: Response,
    user: User
  ): Promise<VerificationResult> {
    const { purpose } = context
    const { id: userId } = user

    // Ưu tiên 2FA nếu user đã enable
    if (user.twoFactorEnabled) {
      this.logger.debug(`[initiateOtpOr2faFlow] 2FA enabled for user ${userId}. Initiating 2FA flow.`)
      const sltToken = await this.sltService.createAndStoreSltToken({ ...context })
      this.cookieService.setSltCookie(res, sltToken, purpose)
      return {
        message: 'auth.success.login.2faRequired',
        data: { verificationType: '2FA' }
      }
    }

    // Fallback sang OTP qua email
    this.logger.debug(`[initiateOtpOr2faFlow] 2FA not enabled for user ${userId}. Initiating OTP flow.`)
    return this.initiateOtpFlow(context, res)
  }

  /**
   * Gửi lại mã xác thực cho user
   *
   * Xử lý yêu cầu resend OTP/2FA code. Validate SLT token hiện có
   * và khởi tạo lại luồng gửi mã mà không tạo SLT mới.
   *
   * @param sltCookieValue - SLT token từ cookie
   * @param ipAddress - Địa chỉ IP của user
   * @param userAgent - User agent của browser
   * @param res - Response object để reset SLT cookie
   * @returns Kết quả resend code
   */
  async reInitiateVerification(
    sltCookieValue: string,
    ipAddress: string,
    userAgent: string,
    res: Response
  ): Promise<VerificationResult> {
    this.logger.debug(`[reInitiateVerification] Re-initiating verification from SLT.`)
    const sltContext = await this.sltService.validateSltFromCookieAndGetContext(sltCookieValue, ipAddress, userAgent)

    // 2FA không cần gửi email - chỉ trả về thông báo
    if (sltContext.metadata?.twoFactorMethod) {
      this.logger.debug('[reInitiateVerification] Context is 2FA. No email will be sent.')
      return {
        message: 'auth.success.login.2faRequired',
        data: { verificationType: '2FA' }
      }
    }

    if (!sltContext.email) {
      throw AuthError.EmailMissingInSltContext()
    }

    await this.otpService.sendOTP(sltContext.email, sltContext.purpose, sltContext)
    const newSltToken = await this.sltService.createAndStoreSltToken(sltContext) // Re-create to invalidate old
    this.cookieService.setSltCookie(res, newSltToken, sltContext.purpose)

    return {
      message: 'auth.success.otp.resend',
      data: { verificationType: 'OTP' }
    }
  }

  /**
   * Xác minh mã OTP/2FA do người dùng cung cấp
   *
   * Entry point chính cho xác minh mã. Bao bọc toàn bộ flow trong try-catch
   * để đảm bảo cleanup (xóa cookie) khi có lỗi.
   *
   * @param sltCookieValue - SLT token từ cookie
   * @param code - Mã xác thực do người dùng nhập
   * @param ipAddress - Địa chỉ IP của người dùng
   * @param userAgent - User agent của người dùng
   * @param res - Response object để quản lý cookie
   * @param additionalMetadata - Metadata bổ sung
   * @returns Kết quả cuối cùng sau khi xác minh thành công
   */
  async verifyCode(
    sltCookieValue: string,
    code: string,
    ipAddress: string,
    userAgent: string,
    res: Response,
    additionalMetadata?: Record<string, any>
  ): Promise<VerificationResult> {
    this.logger.debug(`[verifyCode] Starting verification process.`)
    try {
      return await this._verificationFlow(sltCookieValue, code, ipAddress, userAgent, res, additionalMetadata)
    } catch (error) {
      this.logger.error(`[verifyCode] Flow failed: ${error.message}`, error.stack)

      if (error instanceof ApiException) {
        const terminalSltErrorCodes = [
          'AUTH_SLT_EXPIRED',
          'AUTH_SLT_INVALID',
          'AUTH_SLT_ALREADY_USED',
          'AUTH_SLT_MAX_ATTEMPTS_EXCEEDED',
          'AUTH_SLT_INVALID_PURPOSE',
          'AUTH_EMAIL_MISSING_IN_CONTEXT'
        ]

        if (terminalSltErrorCodes.includes(error.code)) {
          this.cookieService.clearSltCookie(res)
        }
        // Always re-throw the original, structured error
        throw error
      }

      // For unexpected, non-API errors, clear cookie and throw a generic 500
      this.cookieService.clearSltCookie(res)
      throw GlobalError.InternalServerError()
    }
  }

  /**
   * Xử lý luồng chính của verification
   */
  private async _verificationFlow(
    sltCookieValue: string,
    code: string,
    ipAddress: string,
    userAgent: string,
    res: Response,
    additionalMetadata?: Record<string, any>
  ): Promise<VerificationResult> {
    const sltContext = await this.sltService.validateSltFromCookieAndGetContext(sltCookieValue, ipAddress, userAgent)

    if (additionalMetadata) {
      sltContext.metadata = { ...sltContext.metadata, ...additionalMetadata }
    }

    await this.verifyAuthenticationCode(sltContext, code)
    const result = await this.handlePostVerificationActions(sltContext, code, res, sltCookieValue)

    // Cleanup SLT cookie cho hầu hết cases (trừ register/reset password)
    if (!this.shouldKeepSltCookie(sltContext.purpose)) {
      this.cookieService.clearSltCookie(res)
    }

    return result
  }

  /**
   * Kiểm tra có nên giữ SLT cookie hay không
   */
  private shouldKeepSltCookie(purpose: TypeOfVerificationCodeType): boolean {
    return purpose === TypeOfVerificationCode.REGISTER || purpose === TypeOfVerificationCode.RESET_PASSWORD
  }

  /**
   * Xác minh mã authentication (OTP hoặc 2FA)
   */
  private async verifyAuthenticationCode(sltContext: SltContextData & { sltJti: string }, code: string): Promise<void> {
    const { userId, purpose, metadata } = sltContext
    const { twoFactorMethod, totpSecret } = metadata || {}

    // Xác định phương thức xác thực và thực hiện
    if (twoFactorMethod && (twoFactorMethod as string) !== 'EMAIL') {
      this.logger.debug(`Verifying with two-factor method: ${twoFactorMethod}`)
      await this.verifyWith2FA(code, userId, totpSecret, twoFactorMethod, purpose)
    } else {
      this.logger.debug(`Verifying with OTP method for purpose: ${purpose}`)
      await this.verifyWithOtp(code, sltContext)
    }
  }

  /**
   * Xác minh mã OTP qua email
   */
  private async verifyWithOtp(code: string, sltContext: SltContextData): Promise<void> {
    if (!sltContext.email) {
      this.logger.error(`Email is missing in SLT context for OTP verification. UserID: ${sltContext.userId}`)
      throw AuthError.EmailMissingInSltContext()
    }
    await this.otpService.verifyOTP(sltContext.email, code, sltContext.purpose)
  }

  /**
   * Xác minh mã 2FA (TOTP hoặc Recovery)
   */
  private async verifyWith2FA(
    code: string,
    userId: number,
    totpSecret: string | undefined,
    method?: string,
    purpose?: TypeOfVerificationCodeType
  ): Promise<void> {
    // Ensure method is a valid enum member
    const effectiveMethod: TwoFactorMethodType =
      method && Object.values(TwoFactorMethodType).includes(method as TwoFactorMethodType)
        ? (method as TwoFactorMethodType)
        : TwoFactorMethodType.AUTHENTICATOR_APP

    this.logger.debug(`verifyWith2FA for user ${userId}, method: ${effectiveMethod}, purpose: ${purpose || 'N/A'}`)

    // Verify the code using the central 2FA service
    const isValid = await this.twoFactorService.verifyCode(code, {
      userId: userId,
      method: effectiveMethod,
      secret: totpSecret // Pass the secret from SLT if available
    })

    if (!isValid) {
      this.logger.warn(`2FA verification failed for user ${userId} with method ${effectiveMethod}.`)
      throw AuthError.InvalidOTP() // Use a generic "invalid code" error
    }

    this.logger.log(`2FA verification successful for user ${userId} with method ${effectiveMethod}.`)
  }

  /**
   * Xử lý các actions sau khi xác thực thành công
   */
  private async handlePostVerificationActions(
    sltContext: SltContextData & { sltJti: string },
    code: string,
    res: Response,
    sltCookieValue?: string
  ): Promise<VerificationResult> {
    const { purpose } = sltContext
    this.logger.debug(`[handlePostActions] Executing action for purpose: ${purpose}`)

    // Finalize SLT cho các purpose không cần giữ cookie
    if (!this.shouldKeepSltCookie(sltContext.purpose)) {
      await this.sltService.finalizeSlt(sltContext.sltJti)
    }

    const handler = this.VERIFICATION_ACTION_HANDLERS[purpose]
    if (handler) {
      return handler(sltContext, code, res, sltCookieValue)
    }

    // Fallback cho purpose không có handler
    this.logger.warn(`No post-verification handler found for purpose: ${sltContext.purpose}`)
    await this.sltService.finalizeSlt(sltContext.sltJti)
    return { message: 'auth.success.otp.verified' }
  }

  // ===================================================================
  // POST-VERIFICATION ACTION HANDLERS
  // ===================================================================

  /**
   * Xử lý đăng nhập sau khi xác thực thành công
   * Hoàn tất quá trình đăng nhập và tạo session
   */
  private async handleLoginVerification(
    userId: number,
    deviceId: number,
    rememberMe: boolean,
    ipAddress: string,
    userAgent: string,
    res: Response
  ): Promise<VerificationResult> {
    if (!this.loginFinalizerService) {
      throw AuthError.ServiceNotAvailable('LoginFinalizerService')
    }

    const loginPayload: ILoginFinalizationPayload = {
      userId,
      deviceId,
      rememberMe,
      ipAddress,
      userAgent
    }

    const loginResult = await this.loginFinalizerService.finalizeLoginAfterVerification(loginPayload, res)

    // Cập nhật trạng thái trusted cho device nếu user chọn remember me
    if (rememberMe) {
      await this.deviceRepository.updateDeviceTrustStatus(deviceId, true)
    }

    return loginResult
  }

  /**
   * Xử lý revoke sessions sau khi xác thực thành công
   */
  private async handleRevokeSessionsVerification(
    context: SltContextData,
    code: string,
    res: Response
  ): Promise<VerificationResult> {
    const { userId, metadata, ipAddress, userAgent, email } = context
    const { sessionIds, deviceIds, excludeCurrentSession, currentSessionId, currentDeviceId } = metadata || {}

    if (!sessionIds && !deviceIds) {
      throw GlobalError.BadRequest('auth.error.invalidRevokeParams')
    }

    const revokeResult = await this.sessionsService.revokeItems(
      userId,
      { sessionIds, deviceIds, excludeCurrentSession },
      { sessionId: currentSessionId, deviceId: currentDeviceId },
      res
    )

    // Gửi email thông báo revoke session
    await this._sendSessionRevocationEmail(email, userId, ipAddress, userAgent)

    return {
      message: revokeResult.message || 'auth.success.session.revoked',
      data: {
        revokedSessionsCount: revokeResult.data.revokedSessionsCount,
        untrustedDevicesCount: revokeResult.data.untrustedDevicesCount
      }
    }
  }

  /**
   * Xử lý revoke tất cả sessions sau khi xác thực thành công
   */
  private async handleRevokeAllSessionsVerification(
    context: SltContextData,
    code: string,
    res: Response
  ): Promise<VerificationResult> {
    const { userId, metadata, ipAddress, userAgent, email } = context
    const { excludeCurrentSession, currentSessionId, currentDeviceId } = metadata || {}

    const revokeResult = await this.sessionsService.revokeItems(
      userId,
      { revokeAllUserSessions: true, excludeCurrentSession },
      { sessionId: currentSessionId, deviceId: currentDeviceId },
      res
    )

    // Gửi email thông báo revoke session
    await this._sendSessionRevocationEmail(email, userId, ipAddress, userAgent)

    return {
      message: revokeResult.message || 'auth.success.session.allRevoked',
      data: {
        revokedSessionsCount: revokeResult.data.revokedSessionsCount,
        untrustedDevicesCount: revokeResult.data.untrustedDevicesCount
      }
    }
  }

  /**
   * Xử lý unlink Google account sau khi xác thực
   */
  private async handleUnlinkGoogleAccountVerification(context: SltContextData): Promise<VerificationResult> {
    const result = await this.socialService.unlinkGoogleAccount(context.userId)
    return { message: result.message }
  }

  /**
   * Xử lý disable 2FA sau khi xác thực
   */
  private async handleDisable2FAVerification(context: SltContextData): Promise<VerificationResult> {
    const result = await this.twoFactorService.disableVerificationAfterConfirm(context.userId)
    return { message: result.message }
  }

  /**
   * Xử lý setup 2FA sau khi xác thực mã
   */
  private async handleSetup2FAVerification(context: SltContextData, code: string): Promise<VerificationResult> {
    this.logger.log(`Handling post-verification for purpose: SETUP_2FA for user ${context.userId}`)
    const { twoFactorSecret } = context.metadata || {}

    if (!twoFactorSecret) {
      this.logger.error(`2FA secret missing from SLT context for user ${context.userId} during setup confirmation.`)
      throw GlobalError.InternalServerError('auth.error.twoFactorSetupMissingSecret')
    }

    const result = await this.twoFactorService.confirmTwoFactorSetup(
      context.userId,
      code,
      twoFactorSecret,
      context.ipAddress,
      context.userAgent
    )

    return {
      message: 'auth.success.2fa.setupConfirmed',
      data: { recoveryCodes: result.data.recoveryCodes }
    }
  }

  /**
   * Xử lý OTP verified cho đăng ký
   * Cập nhật SLT context để đánh dấu OTP đã được xác thực
   */
  private async handleRegistrationOtpVerified(
    context: SltContextData & { sltJti: string }
  ): Promise<VerificationResult> {
    await this.sltService.updateSltContext(context.sltJti, {
      metadata: { ...context.metadata, otpVerified: 'true' }
    })
    return {
      message: 'auth.success.otp.verified',
      data: { verificationType: 'OTP' }
    }
  }

  /**
   * Xử lý regenerate 2FA recovery codes
   */
  private async handleRegenerate2FACodesVerification(
    context: SltContextData,
    code: string
  ): Promise<VerificationResult> {
    const { userId, ipAddress, userAgent, metadata } = context
    const result = await this.twoFactorService.regenerateRecoveryCodes(
      userId,
      code,
      metadata?.twoFactorMethod,
      ipAddress,
      userAgent
    )
    return {
      message: 'auth.success.2fa.recoveryCodesRegenerated',
      data: { recoveryCodes: result.data.recoveryCodes }
    }
  }

  /**
   * Xử lý reset password OTP verified
   * Cập nhật SLT context để đánh dấu OTP đã được xác thực
   */
  private async handleResetPasswordVerification(
    context: SltContextData & { sltJti: string }
  ): Promise<VerificationResult> {
    await this.sltService.updateSltContext(context.sltJti, {
      metadata: { ...context.metadata, otpVerified: 'true' }
    })
    return {
      message: 'auth.success.otp.verified',
      data: { verificationType: 'OTP' }
    }
  }

  /**
   * Xử lý change password sau khi xác thực
   */
  private async handleChangePasswordVerification(context: SltContextData): Promise<VerificationResult> {
    this.logger.log(`Handling post-verification for purpose: CHANGE_PASSWORD for user ${context.userId}`)

    const { newPassword, revokeAllSessions } = context.metadata || {}

    // Delegate toàn bộ logic cho PasswordService
    await this.passwordService.performPasswordUpdate({
      userId: context.userId,
      newPassword: newPassword,
      revokeAllSessions: revokeAllSessions,
      ipAddress: context.ipAddress,
      userAgent: context.userAgent,
      currentSessionId: context.metadata?.currentSessionId
    })

    // Override message cho change password
    return { message: 'auth.success.password.changeSuccess' }
  }

  // ===================================================================
  // UTILITY METHODS
  // ===================================================================

  /**
   * Khởi tạo luồng OTP - tạo SLT token và gửi email
   */
  private async initiateOtpFlow(context: VerificationContext, res: Response): Promise<VerificationResult> {
    const { email, purpose, metadata, ipAddress, userAgent } = context
    const sltToken = await this.sltService.createAndStoreSltToken(context)

    this.cookieService.setSltCookie(res, sltToken, purpose)
    await this.otpService.sendOTP(email, purpose, { ...metadata, ipAddress, userAgent })

    return {
      message: 'auth.success.otp.sent',
      data: { verificationType: 'OTP' }
    }
  }

  /**
   * Gửi email thông báo revoke session
   * Non-critical operation - không throw error nếu fail
   */
  private async _sendSessionRevocationEmail(
    email: string,
    userId: number,
    ipAddress?: string,
    userAgent?: string
  ): Promise<void> {
    try {
      const user = await this.userRepository.findByIdWithDetails(userId)
      if (!user || !user.email) {
        this.logger.warn(`Cannot send session revocation email, user ${userId} not found or has no email.`)
        return
      }

      const userAgentInfo = this.userAgentService.parse(userAgent)
      const locationInfo = ipAddress ? await this.geolocationService.getLocationFromIP(ipAddress) : null

      await this.emailService.sendSessionRevokeEmail(user.email, {
        userName: user.userProfile?.username ?? user.email.split('@')[0],
        details: [
          {
            label: 'email.Email.common.details.ipAddress',
            value: ipAddress ?? 'N/A'
          },
          {
            label: 'email.Email.common.details.location',
            value: locationInfo?.display ?? 'N/A'
          },
          {
            label: 'email.Email.common.details.device',
            value: `${userAgentInfo.browser || 'Unknown'} on ${userAgentInfo.os || 'Unknown'}`
          }
        ]
      })
    } catch (error) {
      this.logger.error(
        `[AuthVerificationService] Failed to send session revocation email to user ${userId}: ${error.message}`,
        error.stack
      )
      // Không re-throw vì đây là side effect non-critical
    }
  }
}
