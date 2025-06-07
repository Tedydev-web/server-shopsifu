import { Injectable, Logger, Inject, forwardRef } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { RedisService } from 'src/providers/redis/redis.service'
import {
  REDIS_SERVICE,
  TOKEN_SERVICE,
  COOKIE_SERVICE,
  SLT_SERVICE,
  OTP_SERVICE,
  TWO_FACTOR_SERVICE,
  CORE_SERVICE,
  SESSIONS_SERVICE,
  SOCIAL_SERVICE,
  EMAIL_SERVICE
} from 'src/shared/constants/injection.tokens'
import { ICookieService, SltContextData, IOTPService } from 'src/routes/auth/shared/auth.types'
import {
  TypeOfVerificationCode,
  TypeOfVerificationCodeType,
  TwoFactorMethodType
} from 'src/routes/auth/shared/constants/auth.constants'
import { TwoFactorService } from 'src/routes/auth/modules/two-factor/two-factor.service'
import { UserAuthRepository, DeviceRepository } from 'src/routes/auth/shared/repositories'
import { Response } from 'express'
import { AuthError } from 'src/routes/auth/auth.error'
import { I18nService } from 'nestjs-i18n'
import { SLTService } from 'src/routes/auth/shared/services/slt.service'
import { CoreService } from 'src/routes/auth/modules/core/core.service'
import { SessionsService } from 'src/routes/auth/modules/sessions/session.service'
import { SocialService } from 'src/routes/auth/modules/social/social.service'
import { User } from '@prisma/client'
import { EmailService } from 'src/routes/auth/shared/services/common/email.service'
import { ApiException } from 'src/shared/exceptions/api.exception'

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
  success: boolean
  message: string
  sltToken?: string
  verificationType?: 'OTP' | '2FA'
  verifiedMethod?: string
  redirectUrl?: string
  tokens?: {
    accessToken: string
    refreshToken: string
  }
  user?: any
  data?: Record<string, any>
}

type PostVerificationHandler = (
  context: SltContextData & { sltJti: string },
  code: string,
  res: Response,
  sltCookieValue?: string
) => Promise<VerificationResult>

/**
 * @file auth-verification.service.ts
 * @description Dịch vụ trung tâm điều phối tất cả các luồng xác thực đa bước trong ứng dụng.
 * Service này hoạt động như một State Machine, quản lý quá trình từ khi bắt đầu
 * cho đến khi hoàn thành một hành động yêu cầu xác thực (ví dụ: đăng nhập,
 * thực hiện hành động nhạy cảm, đăng ký).
 *
 * @workflow
 * 1.  **Initiation**: Một module khác (ví dụ: CoreService, SessionsService) gọi `initiateVerification`
 *     với một `VerificationContext` chứa tất cả thông tin cần thiết (userId, purpose, v.v.).
 *     - Dựa vào `purpose` và trạng thái người dùng (có bật 2FA không, thiết bị có tin cậy không),
 *       service sẽ quyết định có cần xác thực hay không.
 *     - Nếu cần, nó sẽ tạo một Short-Lived Token (SLT), lưu context vào Redis, đặt SLT vào cookie
 *       và gửi mã OTP/yêu cầu mã 2FA.
 *
 * 2.  **Verification**: Người dùng gửi mã xác thực. `verifyCode` được gọi.
 *     - Service xác thực SLT token từ cookie, lấy lại context từ Redis.
 *     - Dựa vào context, nó gọi `OtpService` hoặc `TwoFactorService` để xác minh mã.
 *
 * 3.  **Post-Verification Action**: Sau khi mã được xác minh, `handlePostVerificationActions` được gọi.
 *     - Sử dụng một `VERIFICATION_ACTION_HANDLERS` map (Strategy Pattern), nó thực thi hành động
 *       cuối cùng tương ứng với `purpose` ban đầu (ví dụ: hoàn tất đăng nhập, vô hiệu hóa 2FA).
 *
 * 4.  **Resending**: Nếu người dùng yêu cầu gửi lại mã, `reInitiateVerification` được gọi, lặp lại
 *     bước 1 với context đã có.
 */
@Injectable()
export class AuthVerificationService {
  private readonly logger = new Logger(AuthVerificationService.name)

  private readonly SENSITIVE_PURPOSES: TypeOfVerificationCodeType[] = [
    TypeOfVerificationCode.DISABLE_2FA,
    TypeOfVerificationCode.REVOKE_SESSIONS,
    TypeOfVerificationCode.REVOKE_ALL_SESSIONS,
    TypeOfVerificationCode.UNLINK_GOOGLE_ACCOUNT,
    TypeOfVerificationCode.REGENERATE_2FA_CODES,
    TypeOfVerificationCode.RESET_PASSWORD
  ]

  private readonly VERIFICATION_ACTION_HANDLERS: Partial<Record<TypeOfVerificationCodeType, PostVerificationHandler>>

  constructor(
    private readonly configService: ConfigService,
    @Inject(REDIS_SERVICE) private readonly redisService: RedisService,
    @Inject(COOKIE_SERVICE) private readonly cookieService: ICookieService,
    @Inject(SLT_SERVICE) private readonly sltService: SLTService,
    @Inject(OTP_SERVICE) private readonly otpService: IOTPService,
    @Inject(TWO_FACTOR_SERVICE) private readonly twoFactorService: TwoFactorService,
    private readonly userAuthRepository: UserAuthRepository,
    private readonly deviceRepository: DeviceRepository,
    private readonly i18nService: I18nService,
    @Inject(forwardRef(() => CoreService)) private readonly coreService: CoreService,
    @Inject(forwardRef(() => SessionsService)) private readonly sessionsService: SessionsService,
    @Inject(forwardRef(() => SocialService)) private readonly socialService: SocialService,
    @Inject(EMAIL_SERVICE) private readonly emailService: EmailService
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
      [TypeOfVerificationCode.RESET_PASSWORD]: this.handleResetPasswordVerification.bind(this)
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
      // Phía controller sẽ trả về phản hồi thực tế với mã QR.
      // Phản hồi này chỉ để xác nhận việc tạo SLT.
      return {
        success: true,
        message: 'SLT for 2FA setup created successfully.'
      }
    }

    const user = await this.userAuthRepository.findById(userId)
    if (!user) {
      throw AuthError.EmailNotFound()
    }

    if (this.SENSITIVE_PURPOSES.includes(purpose) || purpose === TypeOfVerificationCode.LOGIN) {
      return this.handleLoginOrSensitiveActionInitiation(context, res, user)
    }

    this.logger.warn(`[initiateVerification] No defined action for purpose: ${purpose}.`)
    return {
      success: true,
      message: this.i18nService.t('global.success.general.default')
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
      success: true,
      message: this.i18nService.t('global.success.general.default')
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
        success: false,
        message: this.i18nService.t('auth.Auth.Login.2FARequired'),
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
        success: false,
        message: this.i18nService.t('auth.Auth.Login.2FARequired'),
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
      success: false,
      message: this.i18nService.t('auth.Auth.Otp.SentSuccessfully'),
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
      throw AuthError.InternalServerError()
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
    this.logger.debug(`[verifyAuthCode] Verifying code for purpose: ${sltContext.purpose}`)
    try {
      if (sltContext.purpose === TypeOfVerificationCode.SETUP_2FA) {
        await this._verifyWithTwoFactor(
          code,
          sltContext.userId,
          sltContext.metadata?.secret,
          sltContext.metadata?.twoFactorMethod
        )
        return
      }

      const user =
        sltContext.purpose === TypeOfVerificationCode.REGISTER
          ? null
          : await this.userAuthRepository.findById(sltContext.userId)

      if (sltContext.purpose !== TypeOfVerificationCode.REGISTER && !user) {
        throw AuthError.EmailNotFound()
      }

      if (user?.twoFactorEnabled) {
        await this._verifyWithTwoFactor(
          code,
          user.id,
          sltContext.metadata?.secret,
          sltContext.metadata?.twoFactorMethod
        )
      } else {
        await this._verifyWithOtp(code, sltContext)
      }
    } catch (error) {
      await this.sltService.incrementSltAttempts(sltContext.sltJti)
      throw error
    }
  }

  private async _verifyWithOtp(code: string, sltContext: SltContextData): Promise<void> {
    if (!sltContext.email) throw AuthError.EmailMissingInSltContext()
    const isValid = await this.otpService.verifyOTP(
      sltContext.email,
      code,
      sltContext.purpose,
      sltContext.userId,
      sltContext.ipAddress,
      sltContext.userAgent
    )
    if (!isValid) throw AuthError.InvalidOTP()
  }

  private async _verifyWithTwoFactor(
    code: string,
    userId: number,
    secret?: string,
    method?: 'TOTP' | 'RECOVERY'
  ): Promise<void> {
    const context = secret ? { userId, secret, method: 'TOTP' } : { userId, method: method || 'TOTP' }
    // Chỉ cần gọi service, nó sẽ tự throw lỗi nếu không hợp lệ
    await this.twoFactorService.verifyCode(code, context)
  }

  private async handlePostVerificationActions(
    sltContext: SltContextData & { sltJti: string },
    code: string,
    res: Response,
    sltCookieValue?: string
  ): Promise<VerificationResult> {
    const { purpose } = sltContext
    this.logger.debug(`[handlePostActions] Executing action for purpose: ${purpose}`)

    if (purpose !== TypeOfVerificationCode.REGISTER) {
      await this.sltService.finalizeSlt(sltContext.sltJti)
    }

    const handler = this.VERIFICATION_ACTION_HANDLERS[purpose]
    if (handler) {
      return handler(sltContext, code, res, sltCookieValue)
    }

    this.logger.warn(`[handlePostActions] Unhandled purpose: ${purpose}.`)
    return {
      success: true,
      message: this.i18nService.t('global.success.general.default')
    }
  }

  private async handleLoginVerification(
    userId: number,
    deviceId: number,
    rememberMe: boolean,
    ipAddress: string,
    userAgent: string,
    res: Response
  ): Promise<VerificationResult> {
    if (!this.coreService) {
      throw AuthError.InternalServerError('CoreService is not available')
    }
    const loginResult = await this.coreService.finalizeLoginAfterVerification(
      userId,
      deviceId,
      rememberMe,
      res,
      ipAddress,
      userAgent
    )

    if (rememberMe) {
      await this.deviceRepository.updateDeviceTrustStatus(deviceId, true)
    }

    return {
      success: true,
      message: loginResult.message,
      data: loginResult.data
    }
  }

  private async handleRevokeSessionsVerification(context: SltContextData): Promise<VerificationResult> {
    const { userId, metadata, ipAddress, userAgent, email } = context
    const { sessionIds, deviceIds, excludeCurrentSession, currentSessionId, currentDeviceId } = metadata || {}
    if (!sessionIds && !deviceIds) throw AuthError.InsufficientRevocationData()

    const revokeResult = await this.sessionsService.revokeItems(
      userId,
      { sessionIds, deviceIds, excludeCurrentSession },
      { sessionId: currentSessionId, deviceId: currentDeviceId }
    )

    const user = await this.userAuthRepository.findById(userId, { userProfile: true })
    await this.emailService.sendSessionRevokeEmail(email, {
      userName: user?.userProfile?.username ?? email.split('@')[0],
      details: [
        { label: this.i18nService.t('email.Email.common.details.ipAddress'), value: ipAddress ?? 'N/A' },
        { label: this.i18nService.t('email.Email.common.details.device'), value: userAgent ?? 'N/A' }
      ]
    })

    return {
      success: true,
      message: revokeResult.message || this.i18nService.t('auth.Auth.Session.RevokedSuccessfully')
    }
  }

  private async handleRevokeAllSessionsVerification(context: SltContextData): Promise<VerificationResult> {
    const { userId, metadata, ipAddress, userAgent, email } = context
    const { excludeCurrentSession, currentSessionId, currentDeviceId } = metadata || {}
    const revokeResult = await this.sessionsService.revokeItems(
      userId,
      { revokeAllUserSessions: true, excludeCurrentSession },
      { sessionId: currentSessionId, deviceId: currentDeviceId }
    )

    const user = await this.userAuthRepository.findById(userId, { userProfile: true })
    await this.emailService.sendSessionRevokeEmail(email, {
      userName: user?.userProfile?.username ?? email.split('@')[0],
      details: [
        { label: this.i18nService.t('email.Email.common.details.ipAddress'), value: ipAddress ?? 'N/A' },
        { label: this.i18nService.t('email.Email.common.details.device'), value: userAgent ?? 'N/A' }
      ]
    })

    return {
      success: true,
      message: revokeResult.message || this.i18nService.t('auth.Auth.Session.AllRevoked')
    }
  }

  private async handleUnlinkGoogleAccountVerification(context: SltContextData): Promise<VerificationResult> {
    const result = await this.socialService.unlinkGoogleAccount(context.userId)
    return {
      success: result.success,
      message: result.message
    }
  }

  private async handleDisable2FAVerification(context: SltContextData): Promise<VerificationResult> {
    await this.twoFactorService.disableVerification(context.userId)
    return {
      success: true,
      message: this.i18nService.t('auth.Auth.2FA.Disable.Success')
    }
  }

  private async handleSetup2FAVerification(context: SltContextData, code: string): Promise<VerificationResult> {
    const { userId, metadata, ipAddress, userAgent } = context
    const secret = metadata?.secret
    if (!secret) throw AuthError.InternalServerError('Missing 2FA secret for setup.')
    const result = await this.twoFactorService.confirmTwoFactorSetup(userId, code, secret, ipAddress, userAgent)
    return {
      success: true,
      message: result.message,
      data: { recoveryCodes: result.recoveryCodes }
    }
  }

  private async handleRegistrationOtpVerified(
    context: SltContextData & { sltJti: string }
  ): Promise<VerificationResult> {
    await this.sltService.updateSltContext(context.sltJti, {
      metadata: { ...context.metadata, otpVerified: 'true' }
    })
    return {
      success: true,
      message: this.i18nService.t('auth.Auth.Otp.Verified')
    }
  }

  private async handleRegenerate2FACodesVerification(context: SltContextData): Promise<VerificationResult> {
    const { userId, ipAddress, userAgent } = context
    const recoveryCodes = await this.twoFactorService.regenerateRecoveryCodes(userId, ipAddress, userAgent)
    return {
      success: true,
      message: this.i18nService.t('auth.Auth.Error.2FA.RecoveryCodesRegenerated'),
      data: { recoveryCodes }
    }
  }

  private async handleResetPasswordVerification(
    context: SltContextData & { sltJti: string }
  ): Promise<VerificationResult> {
    await this.sltService.updateSltContext(context.sltJti, {
      metadata: { ...context.metadata, otpVerified: 'true' }
    })
    return {
      success: true,
      message: this.i18nService.t('auth.Auth.Otp.Verified')
    }
  }

  private async initiateOtpFlow(context: VerificationContext, res: Response): Promise<VerificationResult> {
    const { email, purpose, metadata, ipAddress, userAgent } = context
    const sltToken = await this.sltService.createAndStoreSltToken(context)

    this.cookieService.setSltCookie(res, sltToken, purpose)

    await this.otpService.sendOTP(email, purpose, { ...metadata, ipAddress, userAgent })

    return {
      success: false,
      message: this.i18nService.t('auth.Auth.Otp.SentSuccessfully'),
      data: { verificationType: 'OTP' }
    }
  }
}
