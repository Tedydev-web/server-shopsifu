import { Injectable, Logger, Inject, forwardRef } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { RedisService } from '../../../shared/providers/redis/redis.service'
import {
  COOKIE_SERVICE,
  SLT_SERVICE,
  OTP_SERVICE,
  TWO_FACTOR_SERVICE,
  EMAIL_SERVICE,
  GEOLOCATION_SERVICE,
  USER_AGENT_SERVICE
} from '../../../shared/constants/injection.tokens'
import {
  ICookieService,
  SltContextData,
  IOTPService,
  ILoginFinalizationPayload,
  ILoginFinalizerService,
  LOGIN_FINALIZER_SERVICE
} from '../auth.types'
import { TypeOfVerificationCode, TypeOfVerificationCodeType } from '../auth.constants'
import { TwoFactorService } from './two-factor.service'
import { DeviceRepository } from 'src/shared/repositories/device.repository'
import { Response } from 'express'
import { AuthError } from '../auth.error'
import { I18nService } from 'nestjs-i18n'
import { SLTService } from '../../../shared/services/slt.service'
import { SessionsService } from './session.service'
import { SocialService } from './social.service'
import { TwoFactorMethodType, User } from '@prisma/client'
import { EmailService } from '../../../shared/services/email.service'
import { ApiException } from '../../../shared/exceptions/api.exception'
import { GeolocationService } from '../../../shared/services/geolocation.service'
import { UserAgentService } from '../../../shared/services/user-agent.service'
import { GlobalError } from 'src/shared/global.error'
import { PasswordService } from './password.service'
import { I18nTranslations } from 'src/generated/i18n.generated'
import { UserRepository } from 'src/routes/user/user.repository'

export interface VerificationContext {
  userId: number
  deviceId: number
  email: string
  ipAddress: string
  userAgent: string
  purpose: TypeOfVerificationCodeType
  metadata?: Record<string, any>
  rememberMe?: boolean
}

export interface VerificationResult {
  message: string
  data?: Record<string, any>
}

type PostVerificationHandler = (
  context: SltContextData & { sltJti: string },
  code: string,
  res: Response,
  sltCookieValue?: string
) => Promise<VerificationResult>

@Injectable()
export class AuthVerificationService {
  private readonly logger = new Logger(AuthVerificationService.name)

  private readonly SENSITIVE_PURPOSES: TypeOfVerificationCodeType[] = [
    TypeOfVerificationCode.DISABLE_2FA,
    TypeOfVerificationCode.REVOKE_SESSIONS,
    TypeOfVerificationCode.REVOKE_ALL_SESSIONS,
    TypeOfVerificationCode.UNLINK_GOOGLE_ACCOUNT,
    TypeOfVerificationCode.REGENERATE_2FA_CODES,
    TypeOfVerificationCode.RESET_PASSWORD,
    TypeOfVerificationCode.CHANGE_PASSWORD
  ]

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
    this.VERIFICATION_ACTION_HANDLERS = {
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

  /**
   * @description **Bước 1: Bắt đầu một luồng xác thực.**
   * Đây là cổng vào chính cho tất cả các hành động cần xác thực.
   * Nó xác định xem có cần xác thực hay không và bắt đầu luồng OTP hoặc 2FA nếu cần.
   * @param {VerificationContext} context - Ngữ cảnh của yêu cầu xác thực.
   * @param {Response} res - Đối tượng Response của Express để set cookie.
   * @returns {Promise<VerificationResult>} Kết quả của việc khởi tạo, có thể là đăng nhập thành công
   * (nếu không cần xác thực) hoặc yêu cầu xác thực.
   */
  async initiateVerification(context: VerificationContext, res: Response): Promise<VerificationResult> {
    const { userId, purpose } = context
    this.logger.debug(`[initiateVerification] UserID: ${userId}, Purpose: ${purpose}`)

    if (purpose === TypeOfVerificationCode.REGISTER) {
      return this.handleRegistrationInitiation(context, res)
    }

    if (purpose === TypeOfVerificationCode.SETUP_2FA) {
      this.logger.debug(`[initiateVerification] Bắt đầu luồng thiết lập 2FA. Đang tạo SLT.`)
      const sltToken = await this.sltService.createAndStoreSltToken(context)
      this.cookieService.setSltCookie(res, sltToken, purpose)
      const result = await this.twoFactorService.generateSetupDetails(context.userId)

      // Cập nhật secret vào SLT context để xác minh ở bước sau
      await this.sltService.updateSltContext(sltToken, {
        metadata: { ...context.metadata, twoFactorSecret: result.data.secret }
      })

      return {
        message: 'auth.success.2fa.setupInitiated',
        data: {
          qrCode: result.data.qrCode,
          secret: result.data.secret // Chỉ trả về ở môi trường dev để dễ test
        }
      }
    }

    const user = await this.userRepository.findById(userId)
    if (!user) {
      throw AuthError.EmailNotFound()
    }

    if (this.SENSITIVE_PURPOSES.includes(purpose) || purpose === TypeOfVerificationCode.LOGIN) {
      return this.handleLoginOrSensitiveActionInitiation(context, res, user)
    }

    this.logger.warn(`[initiateVerification] No defined action for purpose: ${purpose}.`)
    return {
      message: 'global.general.success.default'
    }
  }

  private handleRegistrationInitiation(context: VerificationContext, res: Response): Promise<VerificationResult> {
    this.logger.debug(`[handleRegistrationInitiation] Initiating registration flow for email ${context.email}`)
    return this.initiateOtpFlow(context, res)
  }

  private async handleLoginOrSensitiveActionInitiation(
    context: VerificationContext,
    res: Response,
    user: User
  ): Promise<VerificationResult> {
    const { userId, deviceId, purpose, metadata, ipAddress, userAgent, rememberMe } = context

    if (this.SENSITIVE_PURPOSES.includes(purpose)) {
      this.logger.debug(`[handleLoginOrSensitiveAction] Sensitive action (${purpose}) requires verification.`)
      return this.initiateOtpOr2faFlow(context, res, user)
    }

    if (purpose === TypeOfVerificationCode.LOGIN) {
      const isDeviceTrusted = await this.deviceRepository.isDeviceTrustValid(deviceId)
      const forceVerification = metadata?.forceVerification === true

      if (forceVerification || !isDeviceTrusted) {
        this.logger.log(
          `[handleLoginOrSensitiveAction] Verification required for UserID: ${user.id}. Force: ${forceVerification}, Trusted: ${isDeviceTrusted}`
        )
        return this.initiateOtpOr2faFlow(context, res, user)
      }

      this.logger.debug(`[handleLoginOrSensitiveAction] Trusted device login for UserID: ${user.id}. Skipping OTP/2FA.`)
      return this.handleLoginVerification(userId, deviceId, rememberMe ?? false, ipAddress, userAgent, res)
    }

    this.logger.warn(`[handleLoginOrSensitiveAction] No defined action for purpose: ${purpose}.`)
    return {
      message: 'global.general.success.default'
    }
  }

  private async initiateOtpOr2faFlow(
    context: VerificationContext,
    res: Response,
    user: User
  ): Promise<VerificationResult> {
    const { purpose } = context
    const { id: userId } = user

    if (user.twoFactorEnabled) {
      this.logger.debug(`[initiateOtpOr2faFlow] 2FA enabled for user ${userId}. Initiating 2FA flow.`)
      const sltToken = await this.sltService.createAndStoreSltToken({ ...context })
      this.cookieService.setSltCookie(res, sltToken, purpose)
      return {
        message: 'auth.success.login.2faRequired',
        data: { verificationType: '2FA' }
      }
    }

    this.logger.debug(`[initiateOtpOr2faFlow] 2FA not enabled for user ${userId}. Initiating OTP flow.`)
    return this.initiateOtpFlow(context, res)
  }

  /**
   * @description **Gửi lại mã xác thực.**
   * Xử lý yêu cầu gửi lại mã OTP hoặc 2FA từ người dùng.
   * Nó xác thực SLT token hiện có và bắt đầu lại luồng gửi mã.
   * @param {string} sltCookieValue - Giá trị của SLT token từ cookie.
   * @param {string} ipAddress - Địa chỉ IP của người dùng.
   * @param {string} userAgent - User agent của người dùng.
   * @param {Response} res - Đối tượng Response để set lại SLT cookie mới.
   * @returns {Promise<VerificationResult>} Kết quả yêu cầu gửi lại mã.
   */
  async reInitiateVerification(
    sltCookieValue: string,
    ipAddress: string,
    userAgent: string,
    res: Response
  ): Promise<VerificationResult> {
    this.logger.debug(`[reInitiateVerification] Re-initiating verification from SLT.`)
    const sltContext = await this.sltService.validateSltFromCookieAndGetContext(sltCookieValue, ipAddress, userAgent)

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
   * @description **Bước 2: Xác minh mã do người dùng cung cấp.**
   * Đây là phương thức chính để xử lý việc xác minh mã OTP/2FA.
   * Nó bao bọc toàn bộ flow trong một try-catch block để đảm bảo dọn dẹp (xóa cookie) khi có lỗi.
   * @param {string} sltCookieValue - Giá trị của SLT token từ cookie.
   * @param {string} code - Mã xác thực do người dùng nhập.
   * @param {string} ipAddress - Địa chỉ IP của người dùng.
   * @param {string} userAgent - User agent của người dùng.
   * @param {Response} res - Đối tượng Response của Express.
   * @param {Record<string, any>} [additionalMetadata] - Metadata bổ sung có thể được thêm vào trong quá trình.
   * @returns {Promise<VerificationResult>} Kết quả cuối cùng của hành động sau khi xác minh thành công.
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

    if (
      sltContext.purpose !== TypeOfVerificationCode.REGISTER &&
      sltContext.purpose !== TypeOfVerificationCode.RESET_PASSWORD
    ) {
      this.cookieService.clearSltCookie(res)
    }

    return result
  }

  private async verifyAuthenticationCode(sltContext: SltContextData & { sltJti: string }, code: string): Promise<void> {
    const { userId, purpose, metadata } = sltContext
    const { twoFactorMethod, totpSecret } = metadata || {}

    // Xác định phương thức xác thực và thực hiện
    if (twoFactorMethod && (twoFactorMethod as string) !== 'EMAIL') {
      this.logger.debug(`Verifying with two-factor method: ${twoFactorMethod}`)
      await this._verifyWithTwoFactor(code, userId, totpSecret, twoFactorMethod, purpose)
    } else {
      this.logger.debug(`Verifying with OTP method for purpose: ${purpose}`)
      await this._verifyWithOtp(code, sltContext)
    }
  }

  /**
   * Helper function to verify OTP
   */
  private async _verifyWithOtp(code: string, sltContext: SltContextData): Promise<void> {
    if (!sltContext.email) {
      this.logger.error(`Email is missing in SLT context for OTP verification. UserID: ${sltContext.userId}`)
      throw AuthError.EmailMissingInSltContext()
    }
    await this.otpService.verifyOTP(sltContext.email, code, sltContext.purpose)
  }

  /**
   * Helper function to verify a 2FA code (TOTP or Recovery)
   */
  private async _verifyWithTwoFactor(
    code: string,
    userId: number,
    totpSecret: string | undefined, // Secret from SLT metadata
    method?: string, // Method from SLT metadata
    purpose?: TypeOfVerificationCodeType
  ): Promise<void> {
    // Ensure method is a valid enum member
    const effectiveMethod: TwoFactorMethodType =
      method && Object.values(TwoFactorMethodType).includes(method as TwoFactorMethodType)
        ? (method as TwoFactorMethodType)
        : TwoFactorMethodType.AUTHENTICATOR_APP

    this.logger.debug(
      `_verifyWithTwoFactor for user ${userId}, method: ${effectiveMethod}, purpose: ${purpose || 'N/A'}`
    )

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
   * Handles post-verification actions based on the purpose.
   */
  private async handlePostVerificationActions(
    sltContext: SltContextData & { sltJti: string },
    code: string,
    res: Response,
    sltCookieValue?: string
  ): Promise<VerificationResult> {
    const { purpose } = sltContext
    this.logger.debug(`[handlePostActions] Executing action for purpose: ${purpose}`)

    if (
      sltContext.purpose !== TypeOfVerificationCode.REGISTER &&
      sltContext.purpose !== TypeOfVerificationCode.RESET_PASSWORD
    ) {
      await this.sltService.finalizeSlt(sltContext.sltJti)
    }

    const handler = this.VERIFICATION_ACTION_HANDLERS[purpose]
    if (handler) {
      return handler(sltContext, code, res, sltCookieValue)
    }

    // Fallback for purposes that don't have a specific handler registered
    this.logger.warn(`No post-verification handler found for purpose: ${sltContext.purpose}`)
    await this.sltService.finalizeSlt(sltContext.sltJti)
    return {
      message: 'auth.success.otp.verified' // Generic success message
    }
  }

  // ===========================================================================
  // Post-Verification Action Handlers
  // ===========================================================================

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

    if (rememberMe) {
      await this.deviceRepository.updateDeviceTrustStatus(deviceId, true)
    }

    return loginResult
  }

  private async handleRevokeSessionsVerification(
    context: SltContextData,
    code: string,
    res: Response
  ): Promise<VerificationResult> {
    const { userId, metadata, ipAddress, userAgent, email } = context
    const { sessionIds, deviceIds, excludeCurrentSession, currentSessionId, currentDeviceId } = metadata || {}
    if (!sessionIds && !deviceIds) throw GlobalError.BadRequest('auth.error.invalidRevokeParams')

    const revokeResult = await this.sessionsService.revokeItems(
      userId,
      { sessionIds, deviceIds, excludeCurrentSession },
      { sessionId: currentSessionId, deviceId: currentDeviceId },
      res
    )

    // Send email notification
    await this._sendSessionRevocationEmail(email, userId, ipAddress, userAgent)

    return {
      message: revokeResult.message || 'auth.success.session.revoked',
      data: {
        revokedSessionsCount: revokeResult.data.revokedSessionsCount,
        untrustedDevicesCount: revokeResult.data.untrustedDevicesCount
      }
    }
  }

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

    // Send email notification
    await this._sendSessionRevocationEmail(email, userId, ipAddress, userAgent)

    return {
      message: revokeResult.message || 'auth.success.session.allRevoked',
      data: {
        revokedSessionsCount: revokeResult.data.revokedSessionsCount,
        untrustedDevicesCount: revokeResult.data.untrustedDevicesCount
      }
    }
  }

  private async handleUnlinkGoogleAccountVerification(context: SltContextData): Promise<VerificationResult> {
    const result = await this.socialService.unlinkGoogleAccount(context.userId)
    return {
      message: result.message
    }
  }

  private async handleDisable2FAVerification(context: SltContextData): Promise<VerificationResult> {
    const result = await this.twoFactorService.disableVerificationAfterConfirm(context.userId)
    return {
      message: result.message
    }
  }

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
      data: {
        recoveryCodes: result.data.recoveryCodes
      }
    }
  }

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

  private async handleChangePasswordVerification(context: SltContextData): Promise<VerificationResult> {
    this.logger.log(`Handling post-verification for purpose: CHANGE_PASSWORD for user ${context.userId}`)

    const { newPassword, revokeAllSessions } = context.metadata || {}

    // Delegate the entire logic to PasswordService
    await this.passwordService.performPasswordUpdate({
      userId: context.userId,
      newPassword: newPassword,
      revokeAllSessions: revokeAllSessions,
      ipAddress: context.ipAddress,
      userAgent: context.userAgent,
      currentSessionId: context.metadata?.currentSessionId
    })

    // The message from performPasswordUpdate is for reset, so we override it for change.
    return { message: 'auth.success.password.changeSuccess' }
  }

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
   * Helper to send session revocation notification email.
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
      // Do not re-throw, as this is a non-critical side effect.
    }
  }
}
