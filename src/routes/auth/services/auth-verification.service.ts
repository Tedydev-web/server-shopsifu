import { Injectable, Logger, Inject, forwardRef } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { RedisService } from 'src/providers/redis/redis.service'
import { REDIS_SERVICE, TOKEN_SERVICE, COOKIE_SERVICE, SLT_SERVICE } from 'src/shared/constants/injection.tokens'
import { ICookieService, ITokenService, SltContextData } from 'src/routes/auth/shared/auth.types'
import {
  TypeOfVerificationCode,
  TypeOfVerificationCodeType,
  TwoFactorMethodType
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
    const { userId, deviceId, email, ipAddress, userAgent, purpose, rememberMe, metadata } = context
    this.logger.debug(`[initiateVerification] UserID: ${userId}, Purpose: ${purpose}`)

    const user = await this.userAuthRepository.findById(userId)
    if (!user) throw AuthError.EmailNotFound()

    // Đối với mục đích REGISTER, không cần kiểm tra thiết bị tin cậy hay hành động nhạy cảm
    if (purpose === TypeOfVerificationCode.REGISTER) {
      this.logger.debug(`[initiateVerification] Registration flow for UserID: ${userId}. Proceeding with OTP.`)
      return this.initiateOtpFlow(context, res)
    }

    // Kiểm tra xem có cần xác thực không
    const isSensitiveAction = this.SENSITIVE_PURPOSES.includes(purpose)
    const isDeviceTrusted = await this.deviceRepository.isDeviceTrustValid(deviceId)
    const needsVerification = isSensitiveAction || (purpose === TypeOfVerificationCode.LOGIN && !isDeviceTrusted)

    if (!needsVerification && purpose === TypeOfVerificationCode.LOGIN) {
      this.logger.debug(`[initiateVerification] Trusted device login for UserID: ${userId}. Skipping verification.`)
      return this.handleLoginVerification(userId, deviceId, rememberMe ?? false, ipAddress, userAgent, res)
    }

    // Nếu cần xác thực, tiến hành theo luồng OTP/2FA
    this.logger.debug(
      `[initiateVerification] Needs verification for UserID: ${userId}. Sensitive: ${isSensitiveAction}`
    )

    const use2FA = user.twoFactorEnabled
    const sltMetadata = { ...metadata, rememberMe, ...(use2FA && { twoFactorMethod: TwoFactorMethodType.TOTP }) }
    const sltToken = await this.sltService.createAndStoreSltToken({ ...context, metadata: sltMetadata })
    this.cookieService.setSltCookie(res, sltToken, purpose)

    let messageKey: I18nPath = 'auth.Auth.Otp.SentSuccessfully'
    if (use2FA) {
      messageKey = 'auth.Auth.2FA.Verify.AskToTrustDevice'
    } else {
      await this.otpService.sendOTP(email, purpose, userId, metadata)
    }

    return {
      success: true,
      message: this.i18nService.t(messageKey),
      sltToken,
      verificationType: use2FA ? '2FA' : 'OTP'
    }
  }

  /**
   * Khởi tạo lại luồng xác thực từ một SLT cookie đã có.
   * Dùng cho chức năng "Gửi lại OTP/mã".
   */
  async reInitiateVerification(sltCookieValue: string, ipAddress: string, userAgent: string, res: Response) {
    this.logger.debug(`[reInitiateVerification] Re-initiating verification from SLT.`)
    const sltContext = await this.sltService.validateSltFromCookieAndGetContext(sltCookieValue, ipAddress, userAgent)

    if (!sltContext.email) {
      throw AuthError.EmailMissingInSltContext()
    }

    // Gọi lại initiateVerification với context đã có, thêm cờ 'resent'
    return this.initiateVerification(
      {
        userId: sltContext.userId,
        deviceId: sltContext.deviceId,
        email: sltContext.email,
        ipAddress,
        userAgent,
        purpose: sltContext.purpose,
        metadata: { ...sltContext.metadata, resent: true }
      },
      res
    )
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
      return result
    } catch (error) {
      this.logger.error(`[verifyCode] Error: ${error.message}`, error.stack)
      // Dù thành công hay thất bại, SLT cũng nên được xóa để tránh dùng lại
      this.cookieService.clearSltCookie(res)
      if (error instanceof AuthError) throw error
      throw AuthError.InternalServerError()
    } finally {
      // Đảm bảo cookie luôn được xóa
      this.cookieService.clearSltCookie(res)
    }
  }

  private async verifyAuthenticationCode(sltContext: SltContextData & { sltJti: string }, code: string): Promise<void> {
    const { userId, purpose, email } = sltContext
    this.logger.debug(`[verifyAuthCode] Verifying code for UserID: ${userId}, Purpose: ${purpose}`)

    const user = await this.userAuthRepository.findById(userId)
    if (!user) throw AuthError.EmailNotFound()

    try {
      if (user.twoFactorEnabled) {
        // Xác thực 2FA
        const { twoFactorMethod = TwoFactorMethodType.TOTP } = sltContext.metadata || {}
        await this.twoFactorService.verifyCode(code, {
          userId,
          method: twoFactorMethod,
          secret: user.twoFactorSecret ?? undefined
        })
      } else {
        // Xác thực OTP
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
      throw error // Ném lại lỗi gốc (InvalidOTP, InvalidTOTP...)
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
    await this.sltService.finalizeSlt(sltContext.sltJti)

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
      case TypeOfVerificationCode.REGENERATE_2FA_CODES:
        return this.handleRegenerate2FACodesVerification(userId, code)

      case TypeOfVerificationCode.REGISTER:
        return this.handleRegistrationOtpVerified(sltContext.sltJti)

      // Các case khác như REGISTER, RESET_PASSWORD có thể xử lý ở đây nếu cần
      // ...

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
    const loginResult = await this.coreService.finalizeLoginAfterVerification(
      userId,
      deviceId,
      rememberMe,
      res,
      ipAddress,
      userAgent
    )
    return {
      success: true,
      message: loginResult.message || this.i18nService.t('auth.Auth.Login.Success' as I18nPath),
      tokens: {
        accessToken: loginResult.accessToken,
        refreshToken: loginResult.refreshToken
      },
      user: loginResult.user
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

  private async handleRegenerate2FACodesVerification(userId: number, code: string): Promise<VerificationResult> {
    const recoveryCodes = await this.twoFactorService.regenerateRecoveryCodes(userId, code)
    return {
      success: true,
      message: this.i18nService.t('auth.Auth.2FA.RecoveryCodesRegenerated' as I18nPath),
      data: { recoveryCodes }
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

  private async handleRegistrationCompletion(
    userId: number,
    metadata?: Record<string, any>
  ): Promise<VerificationResult> {
    if (!metadata || !metadata.password) {
      throw AuthError.InternalServerError('Password missing in registration metadata.')
    }

    await this.coreService.completeRegistration({
      userId,
      password: metadata.password,
      confirmPassword: metadata.confirmPassword,
      firstName: metadata.firstName,
      lastName: metadata.lastName,
      username: metadata.username,
      phoneNumber: metadata.phoneNumber
    })

    return {
      success: true,
      message: this.i18nService.t('auth.Auth.Register.Success' as I18nPath)
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
      success: true,
      message: this.i18nService.t('auth.Auth.Otp.SentSuccessfully'),
      sltToken,
      verificationType: 'OTP'
    }
  }
}
