import { Injectable, Logger, Inject, forwardRef } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { RedisService } from 'src/providers/redis/redis.service'
import { REDIS_SERVICE, TOKEN_SERVICE, COOKIE_SERVICE, SLT_SERVICE } from 'src/shared/constants/injection.tokens'
import { ICookieService, ITokenService, SltContextData } from 'src/routes/auth/shared/auth.types'
import {
  TypeOfVerificationCode,
  TypeOfVerificationCodeType,
  TwoFactorMethodType,
  TwoFactorMethodTypeType
} from 'src/routes/auth/shared/constants/auth.constants'
import { TwoFactorService } from 'src/routes/auth/modules/two-factor/two-factor.service'
import { UserAuthRepository, DeviceRepository } from 'src/routes/auth/shared/repositories'
import { Request, Response } from 'express'
import { AuthError } from 'src/routes/auth/auth.error'
import { I18nService } from 'nestjs-i18n'
import { I18nTranslations, I18nPath } from 'src/generated/i18n.generated'
import { SLTService } from 'src/routes/auth/shared/services/slt.service'
import { CoreService } from 'src/routes/auth/modules/core/core.service'
import { SessionsService } from 'src/routes/auth/modules/sessions/sessions.service'
import { SocialService } from 'src/routes/auth/modules/social/social.service'
import { OtpService } from 'src/routes/auth/modules/otp/otp.service'
import { User } from '@prisma/client'

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

@Injectable()
export class AuthVerificationService {
  private readonly logger = new Logger(AuthVerificationService.name)

  private readonly SENSITIVE_PURPOSES: TypeOfVerificationCodeType[] = [
    TypeOfVerificationCode.DISABLE_2FA,
    TypeOfVerificationCode.REVOKE_SESSIONS,
    TypeOfVerificationCode.REVOKE_ALL_SESSIONS,
    TypeOfVerificationCode.UNLINK_GOOGLE_ACCOUNT,
    TypeOfVerificationCode.REGENERATE_2FA_CODES
  ]

  constructor(
    private readonly configService: ConfigService,
    @Inject(REDIS_SERVICE) private readonly redisService: RedisService,
    @Inject(TOKEN_SERVICE) private readonly tokenService: ITokenService,
    @Inject(COOKIE_SERVICE) private readonly cookieService: ICookieService,
    @Inject(forwardRef(() => OtpService)) private readonly otpService: OtpService,
    @Inject(forwardRef(() => TwoFactorService)) private readonly twoFactorService: TwoFactorService,
    private readonly userAuthRepository: UserAuthRepository,
    private readonly deviceRepository: DeviceRepository,
    private readonly i18nService: I18nService<I18nTranslations>,
    @Inject(SLT_SERVICE) private readonly sltService: SLTService,
    @Inject(forwardRef(() => CoreService)) private readonly coreService: CoreService,
    @Inject(forwardRef(() => SessionsService)) private readonly sessionsService: SessionsService,
    @Inject(forwardRef(() => SocialService)) private readonly socialService: SocialService
  ) {}

  // ===================================================================================
  // BƯỚC 1: KHỞI TẠO LUỒNG XÁC THỰC
  // ===================================================================================

  async initiateVerification(context: VerificationContext, res: Response): Promise<VerificationResult> {
    const { userId, deviceId, purpose, metadata, ipAddress, userAgent, rememberMe } = context
    this.logger.debug(`[initiateVerification] UserID: ${userId}, Purpose: ${purpose}`)

    // Luồng đăng ký luôn cần OTP và không cần kiểm tra user tồn tại
    if (purpose === TypeOfVerificationCode.REGISTER) {
      this.logger.debug(`[initiateVerification] Khởi tạo luồng đăng ký với email ${context.email}`)
      return this.initiateOtpFlow(context, res)
    }

    // Với các trường hợp khác ngoài đăng ký, kiểm tra user
    const user = await this.userAuthRepository.findById(userId)
    if (!user) {
      throw AuthError.EmailNotFound()
    }

    // Các hành động nhạy cảm hoặc đăng nhập sẽ được kiểm tra sâu hơn
    if (this.SENSITIVE_PURPOSES.includes(purpose) || purpose === TypeOfVerificationCode.LOGIN) {
      const isDeviceTrusted = await this.deviceRepository.isDeviceTrustValid(deviceId)
      const forceVerification = metadata?.forceVerification === true

      // Buộc xác thực nếu có cờ, hoặc nếu là đăng nhập trên thiết bị không tin cậy
      if (forceVerification || (purpose === TypeOfVerificationCode.LOGIN && !isDeviceTrusted)) {
        if (forceVerification) {
          this.logger.log(`[initiateVerification] Buộc xác thực cho UserID: ${userId} do cờ 'forceVerification'.`)
        } else {
          this.logger.log(`[initiateVerification] UserID: ${userId} đăng nhập trên thiết bị không tin cậy.`)
        }
        return this.initiateOtpOr2faFlow(context, res, user)
      }

      // Nếu đăng nhập trên thiết bị đã tin cậy và không bị buộc, đăng nhập thẳng
      if (purpose === TypeOfVerificationCode.LOGIN && isDeviceTrusted && !forceVerification) {
        this.logger.debug(
          `[initiateVerification] Đăng nhập trên thiết bị tin cậy cho UserID: ${userId}. Bỏ qua xác thực.`
        )
        return this.handleLoginVerification(userId, deviceId, rememberMe ?? false, ipAddress, userAgent, res)
      }
    }

    // Các trường hợp khác (hành động nhạy cảm trên thiết bị tin cậy) sẽ kích hoạt OTP
    if (this.SENSITIVE_PURPOSES.includes(purpose)) {
      this.logger.debug(
        `[initiateVerification] Hành động nhạy cảm trên thiết bị tin cậy cho UserID: ${userId}. Yêu cầu OTP.`
      )
      return this.initiateOtpOr2faFlow(context, res, user)
    }

    // Mặc định cho các trường hợp không xác định
    this.logger.warn(`[initiateVerification] Không có hành động nào được xác định cho mục đích: ${purpose}.`)
    return {
      success: true,
      message: this.i18nService.t('global.success.general.default' as I18nPath)
    }
  }

  private async initiateOtpOr2faFlow(
    context: VerificationContext,
    res: Response,
    user: User
  ): Promise<VerificationResult> {
    const { purpose } = context
    const { id: userId } = user

    // Logic cốt lõi: Ưu tiên 2FA nếu được bật
    if (user.twoFactorEnabled) {
      this.logger.debug(`[initiateOtpOr2faFlow] 2FA is enabled for user ${userId}. Initiating 2FA flow.`)

      const sltToken = await this.sltService.createAndStoreSltToken({ ...context })
      this.cookieService.setSltCookie(res, sltToken, purpose)

      return {
        success: false,
        message: this.i18nService.t('auth.Auth.Login.2FARequired' as I18nPath),
        data: {
          verificationType: '2FA'
        }
      }
    }

    // Nếu 2FA không được bật, quay lại luồng OTP qua email
    this.logger.debug(`[initiateOtpOr2faFlow] 2FA is not enabled for user ${userId}. Initiating OTP flow.`)
    return this.initiateOtpFlow(context, res)
  }

  /**
   * Khởi tạo lại luồng xác thực từ một SLT cookie đã có.
   * Dùng cho chức năng "Gửi lại OTP/mã".
   */
  async reInitiateVerification(
    sltCookieValue: string,
    ipAddress: string,
    userAgent: string,
    res: Response
  ): Promise<VerificationResult> {
    this.logger.debug(`[reInitiateVerification] Re-initiating verification from SLT.`)
    const sltContext = await this.sltService.validateSltFromCookieAndGetContext(sltCookieValue, ipAddress, userAgent)

    if (!sltContext.email) {
      throw AuthError.EmailMissingInSltContext()
    }

    // Bug fix: Resend the OTP
    await this.otpService.sendOTP(sltContext.email, sltContext.purpose, sltContext.userId, sltContext.metadata)

    // Re-create SLT token to invalidate the old one
    const sltToken = await this.sltService.createAndStoreSltToken(sltContext)
    this.cookieService.setSltCookie(res, sltToken, sltContext.purpose)

    const use2FA = !!sltContext.metadata?.twoFactorMethod

    return {
      success: false, // Not final success, requires OTP verification
      message: 'auth.Auth.Otp.SentSuccessfully',
      data: {
        verificationType: use2FA ? '2FA' : 'OTP'
      }
    }
  }

  // ===================================================================================
  // BƯỚC 2: XÁC MINH MÃ
  // ===================================================================================

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
      const sltContext = await this.sltService.validateSltFromCookieAndGetContext(sltCookieValue, ipAddress, userAgent)

      // Gộp metadata bổ sung vào context trước khi xử lý
      if (additionalMetadata) {
        sltContext.metadata = { ...sltContext.metadata, ...additionalMetadata }
      }

      await this.verifyAuthenticationCode(sltContext, code)
      const result = await this.handlePostVerificationActions(sltContext, code, res, sltCookieValue)

      // Không xóa SLT cookie khi đã xác minh OTP thành công cho quy trình đăng ký
      // vì cookie này vẫn cần thiết cho bước complete-registration
      if (sltContext.purpose !== TypeOfVerificationCode.REGISTER) {
        this.cookieService.clearSltCookie(res)
      }

      return result
    } catch (error) {
      this.logger.error(`[verifyCode] Error: ${error.message}`, error.stack)
      // Khi có lỗi, luôn xóa cookie để tránh sử dụng lại
      this.cookieService.clearSltCookie(res)
      if (error instanceof AuthError) throw error
      throw AuthError.InternalServerError()
    }
  }

  private async verifyAuthenticationCode(sltContext: SltContextData & { sltJti: string }, code: string): Promise<void> {
    const { userId, purpose, email, metadata } = sltContext
    this.logger.debug(`[verifyAuthCode] Verifying code for UserID: ${userId}, Purpose: ${purpose}`)

    try {
      // Xử lý riêng cho quá trình đăng ký
      if (purpose === TypeOfVerificationCode.REGISTER) {
        if (!email) throw AuthError.EmailMissingInSltContext()

        const isValid = await this.otpService.verifyOTP(
          email,
          code,
          purpose,
          userId,
          sltContext.ipAddress,
          sltContext.userAgent
        )
        if (!isValid) throw AuthError.InvalidOTP()
        return
      }

      // Xử lý riêng cho quá trình thiết lập 2FA
      if (purpose === TypeOfVerificationCode.SETUP_2FA) {
        const secret = metadata?.secret
        if (!secret) {
          this.logger.error('[verifyAuthCode] Secret is missing in SLT context for 2FA setup.')
          throw AuthError.InternalServerError('Secret missing for 2FA setup verification.')
        }
        const isValid = await this.twoFactorService.verifyCode(code, {
          userId,
          secret,
          method: TwoFactorMethodType.TOTP
        })
        if (!isValid) {
          throw AuthError.InvalidTOTP()
        }
        return
      }

      // Xử lý cho các trường hợp khác, yêu cầu người dùng tồn tại
      const user = await this.userAuthRepository.findById(userId)
      if (!user) throw AuthError.EmailNotFound()

      if (user.twoFactorEnabled) {
        const isValid = await this.twoFactorService.verifyCode(code, { userId })
        if (!isValid) throw AuthError.InvalidTOTP()
      } else {
        if (!email) throw AuthError.EmailMissingInSltContext()
        const isValid = await this.otpService.verifyOTP(
          email,
          code,
          purpose,
          userId,
          sltContext.ipAddress,
          sltContext.userAgent
        )
        if (!isValid) throw AuthError.InvalidOTP()
      }
    } catch (error) {
      await this.sltService.incrementSltAttempts(sltContext.sltJti)
      throw error
    }
  }

  // ===================================================================================
  // BƯỚC 3: XỬ LÝ HÀNH ĐỘNG SAU XÁC THỰC
  // ===================================================================================

  private async handlePostVerificationActions(
    sltContext: SltContextData & { sltJti: string },
    code: string, // `code` có thể cần cho một số hành động
    res: Response,
    sltCookieValue?: string
  ): Promise<VerificationResult> {
    const { purpose, userId, deviceId, ipAddress, userAgent, metadata } = sltContext
    this.logger.debug(`[handlePostActions] Executing post-verification action for Purpose: ${purpose}`)

    // Đảm bảo SLT được finalize trước khi thực hiện hành động
    // Trừ trường hợp REGISTER, vì quá trình REGISTER cần 2 bước
    if (purpose !== TypeOfVerificationCode.REGISTER) {
      await this.sltService.finalizeSlt(sltContext.sltJti)
    }

    switch (purpose) {
      case TypeOfVerificationCode.LOGIN: {
        const rememberMe = metadata?.rememberMe === true
        return this.handleLoginVerification(userId, deviceId, rememberMe, ipAddress, userAgent, res)
      }
      case TypeOfVerificationCode.REVOKE_SESSIONS:
        return this.handleRevokeSessionsVerification(userId, metadata)

      case TypeOfVerificationCode.REVOKE_ALL_SESSIONS:
        return this.handleRevokeAllSessionsVerification(userId, metadata)

      case TypeOfVerificationCode.UNLINK_GOOGLE_ACCOUNT:
        return this.handleUnlinkGoogleAccountVerification(userId, code, sltCookieValue, res)

      case TypeOfVerificationCode.DISABLE_2FA:
        return this.handleDisable2FAVerification(userId)

      case TypeOfVerificationCode.SETUP_2FA: {
        const secret = metadata?.secret
        if (!secret) throw AuthError.InternalServerError('Missing 2FA secret for setup.')
        return this.handleSetup2FAVerification(userId, code, secret)
      }
      case TypeOfVerificationCode.REGISTER:
        return this.handleRegistrationOtpVerified(sltContext.sltJti)

      default:
        this.logger.warn(`[handlePostActions] Unhandled purpose: ${purpose}.`)
        return {
          success: true,
          message: this.i18nService.t('global.success.general.default' as I18nPath)
        }
    }
  }

  // ===================================================================================
  // CÁC HANDLERS CỤ THỂ CHO TỪNG HÀNH ĐỘNG
  // ===================================================================================

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

    // Nếu người dùng chọn "rememberMe", chúng ta tin cậy thiết bị này
    if (rememberMe) {
      await this.deviceRepository.updateDeviceTrustStatus(deviceId, true)
    }

    return {
      success: true,
      message: loginResult.message,
      data: loginResult.data
    }
  }

  private async handleRevokeSessionsVerification(
    userId: number,
    metadata?: Record<string, any>
  ): Promise<VerificationResult> {
    const { sessionIds, deviceIds, excludeCurrentSession, currentSessionId, currentDeviceId } = metadata || {}
    if (!sessionIds && !deviceIds) throw AuthError.InsufficientRevocationData()

    const revokeResult = await this.sessionsService.revokeItems(
      userId,
      { sessionIds, deviceIds, excludeCurrentSession },
      { sessionId: currentSessionId, deviceId: currentDeviceId }
    )
    return {
      success: true,
      message: revokeResult.message || this.i18nService.t('auth.Auth.Session.RevokedSuccessfully' as I18nPath)
    }
  }

  private async handleRevokeAllSessionsVerification(
    userId: number,
    metadata?: Record<string, any>
  ): Promise<VerificationResult> {
    const { excludeCurrentSession, currentSessionId, currentDeviceId } = metadata || {}
    const revokeResult = await this.sessionsService.revokeItems(
      userId,
      { revokeAllUserSessions: true, excludeCurrentSession },
      { sessionId: currentSessionId, deviceId: currentDeviceId }
    )
    return {
      success: true,
      message: revokeResult.message || this.i18nService.t('auth.Auth.Session.AllRevoked' as I18nPath)
    }
  }

  private async handleUnlinkGoogleAccountVerification(
    userId: number,
    code: string,
    sltToken: string | undefined,
    res: Response
  ): Promise<VerificationResult> {
    const result = await this.socialService.unlinkGoogleAccount(userId)
    return {
      success: result.success,
      message: result.message
    }
  }

  private async handleDisable2FAVerification(userId: number): Promise<VerificationResult> {
    await this.twoFactorService.disableVerification(userId)
    return {
      success: true,
      message: this.i18nService.t('auth.Auth.2FA.Disable.Success' as I18nPath)
    }
  }

  private async handleSetup2FAVerification(
    userId: number,
    totpCode: string,
    secret: string
  ): Promise<VerificationResult> {
    const result = await this.twoFactorService.confirmTwoFactorSetup(userId, totpCode, secret)
    return {
      success: true,
      message: result.message,
      data: { recoveryCodes: result.recoveryCodes }
    }
  }

  private async handleRegistrationOtpVerified(sltJti: string): Promise<VerificationResult> {
    await this.sltService.updateSltContext(sltJti, {
      metadata: { otpVerified: 'true' }
    })
    return {
      success: true,
      message: this.i18nService.t('auth.Auth.Otp.Verified' as I18nPath)
    }
  }

  /**
   * Helper function to centralize OTP flow initiation
   */
  private async initiateOtpFlow(context: VerificationContext, res: Response): Promise<VerificationResult> {
    const { userId, email, purpose, metadata } = context
    const sltToken = await this.sltService.createAndStoreSltToken(context)
    this.cookieService.setSltCookie(res, sltToken, purpose)
    await this.otpService.sendOTP(email, purpose, userId, metadata)

    return {
      success: false, // It's an intermediate step, not final success
      message: this.i18nService.t('auth.Auth.Otp.SentSuccessfully'),
      data: {
        verificationType: 'OTP'
      }
    }
  }
}
