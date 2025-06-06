import { Injectable, Logger, Inject } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { RedisService } from 'src/shared/providers/redis/redis.service'
import { REDIS_SERVICE, EMAIL_SERVICE, TOKEN_SERVICE, COOKIE_SERVICE } from 'src/shared/constants/injection.tokens'
import { ICookieService, ITokenService } from 'src/shared/types/auth.types'
import {
  TypeOfVerificationCodeType,
  TypeOfVerificationCode,
  TwoFactorMethodType
} from 'src/shared/constants/auth.constants'
import { OtpService } from 'src/routes/auth/modules/otp/otp.service'
import { TwoFactorService } from 'src/routes/auth/modules/two-factor/two-factor.service'
import { UserAuthRepository } from 'src/shared/repositories/auth/user-auth.repository'
import { Request, Response } from 'express'
import { AuthError } from 'src/routes/auth/auth.error'
import { SltContextData } from 'src/routes/auth/auth.types'
import { I18nService } from 'nestjs-i18n'
import { SLTService } from './slt.service'
import { CoreService } from 'src/routes/auth/modules/core/core.service'
import { SessionsService } from 'src/routes/auth/modules/sessions/sessions.service'
import { SocialService } from 'src/routes/auth/modules/social/social.service'

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
  sltContext?: SltContextData & { sltJti: string }
  verifiedMethod?: string
  redirectUrl?: string
  requiresDeviceVerification?: boolean
  requiresAdditionalVerification?: boolean
  tokens?: {
    accessToken: string
    refreshToken: string
  }
  user?: any
}

@Injectable()
export class AuthVerificationService {
  private readonly logger = new Logger(AuthVerificationService.name)

  constructor(
    private readonly configService: ConfigService,
    @Inject(REDIS_SERVICE) private readonly redisService: RedisService,
    @Inject(TOKEN_SERVICE) private readonly tokenService: ITokenService,
    @Inject(COOKIE_SERVICE) private readonly cookieService: ICookieService,
    private readonly otpService: OtpService,
    private readonly twoFactorService: TwoFactorService,
    private readonly userAuthRepository: UserAuthRepository,
    private readonly i18nService: I18nService,
    private readonly sltService: SLTService,
    private readonly coreService: CoreService,
    private readonly sessionsService: SessionsService,
    private readonly socialService: SocialService
  ) {}

  /**
   * Khởi tạo quá trình xác thực thích hợp dựa vào loại xác thực và trạng thái 2FA
   */
  async initiateVerification(context: VerificationContext, res: Response): Promise<VerificationResult> {
    const { userId, deviceId, email, ipAddress, userAgent, purpose, metadata } = context

    try {
      // Kiểm tra xem user có tồn tại
      const user = await this.userAuthRepository.findById(userId)

      if (!user) {
        throw AuthError.EmailNotFound()
      }

      // Nếu user đã bật 2FA và loại xác thực này nên dùng 2FA
      if (user.twoFactorEnabled && this.shouldUse2FAForPurpose(purpose)) {
        // Khởi tạo xác thực 2FA
        return this.initiate2FAVerification(context, res)
      } else {
        // Khởi tạo xác thực OTP
        return this.initiateOTPVerification(context, res)
      }
    } catch (error) {
      this.logger.error(`[initiateVerification] Error: ${error.message}`, error.stack)
      if (error instanceof AuthError) throw error
      throw AuthError.InternalServerError()
    }
  }

  /**
   * Kiểm tra xem loại xác thực này có nên sử dụng 2FA không
   */
  private shouldUse2FAForPurpose(purpose: TypeOfVerificationCodeType): boolean {
    // Danh sách các mục đích cần sử dụng 2FA nếu đã bật
    const purposes2FA = [
      TypeOfVerificationCode.LOGIN_UNTRUSTED_DEVICE_2FA,
      TypeOfVerificationCode.DISABLE_2FA,
      TypeOfVerificationCode.REVOKE_SESSIONS_2FA,
      TypeOfVerificationCode.REVOKE_ALL_SESSIONS_2FA,
      TypeOfVerificationCode.UNLINK_GOOGLE_ACCOUNT
    ]

    return purposes2FA.includes(purpose as TypeOfVerificationCode)
  }

  /**
   * Khởi tạo xác thực OTP
   */
  private async initiateOTPVerification(context: VerificationContext, res: Response): Promise<VerificationResult> {
    const { userId, deviceId, email, ipAddress, userAgent, purpose, metadata, rememberMe } = context

    try {
      // Tạo SLT token
      const sltToken = await this.sltService.createAndStoreSltToken({
        userId,
        deviceId,
        ipAddress,
        userAgent,
        purpose,
        email,
        metadata: { ...metadata, rememberMe }
      })

      // Gửi OTP nếu cần
      await this.otpService.sendOTP(email, purpose, userId, metadata)

      // Đặt SLT token vào cookie
      this.cookieService.setSltCookie(res, sltToken, purpose)

      return {
        success: true,
        message: this.i18nService.t('auth.Auth.Otp.SentSuccessfully'),
        sltToken
      }
    } catch (error) {
      this.logger.error(`[initiateOTPVerification] Error: ${error.message}`, error.stack)
      if (error instanceof AuthError) throw error
      throw AuthError.InternalServerError()
    }
  }

  /**
   * Khởi tạo xác thực 2FA
   */
  private async initiate2FAVerification(context: VerificationContext, res: Response): Promise<VerificationResult> {
    const { userId, deviceId, email, ipAddress, userAgent, purpose, metadata, rememberMe } = context

    try {
      // Tạo SLT token với metadata 2FA
      const sltToken = await this.sltService.createAndStoreSltToken({
        userId,
        deviceId,
        ipAddress,
        userAgent,
        purpose,
        email,
        metadata: {
          ...metadata,
          twoFactorMethod: TwoFactorMethodType.TOTP,
          rememberMe
        }
      })

      // Đặt SLT token vào cookie
      this.cookieService.setSltCookie(res, sltToken, purpose)

      return {
        success: true,
        message: this.i18nService.t('auth.Auth.2FA.Verify.AskToTrustDevice'),
        sltToken
      }
    } catch (error) {
      this.logger.error(`[initiate2FAVerification] Error: ${error.message}`, error.stack)
      if (error instanceof AuthError) throw error
      throw AuthError.InternalServerError()
    }
  }

  /**
   * Xác minh mã OTP hoặc 2FA
   */
  async verifyCode(
    sltCookieValue: string,
    code: string,
    ipAddress: string,
    userAgent: string,
    req: Request,
    res: Response
  ): Promise<VerificationResult> {
    try {
      // Xác thực SLT token và lấy context
      const sltContext = await this.sltService.validateSltFromCookieAndGetContext(sltCookieValue, ipAddress, userAgent)

      // Kiểm tra xem user có tồn tại
      const user = await this.userAuthRepository.findById(sltContext.userId)

      if (!user) {
        throw AuthError.EmailNotFound()
      }

      // Xử lý theo loại xác thực
      if (user.twoFactorEnabled && this.shouldUse2FAForPurpose(sltContext.purpose)) {
        // Verify 2FA
        const result = await this.verifyWith2FA(
          sltContext,
          code,
          sltContext.metadata?.twoFactorMethod || TwoFactorMethodType.TOTP,
          ipAddress,
          userAgent,
          sltContext.metadata?.rememberMe === true
        )

        // Xử lý sau khi xác thực 2FA thành công
        return this.handlePostVerificationActions(sltContext, result, ipAddress, userAgent, res)
      } else {
        // Verify OTP
        const result = await this.verifyWithOTP(sltContext, code, ipAddress, userAgent)

        // Xử lý sau khi xác thực OTP thành công
        return this.handlePostVerificationActions(
          sltContext,
          { success: true, sltContext: result },
          ipAddress,
          userAgent,
          res
        )
      }
    } catch (error) {
      this.logger.error(`[verifyCode] Error: ${error.message}`, error.stack)
      if (error instanceof AuthError) throw error
      throw AuthError.InternalServerError()
    }
  }

  /**
   * Xác thực bằng OTP
   */
  private async verifyWithOTP(
    sltContext: SltContextData & { sltJti: string },
    otpCode: string,
    ipAddress: string,
    userAgent: string
  ): Promise<SltContextData & { sltJti: string }> {
    try {
      // Xác minh OTP
      const email = sltContext.email
      if (!email) {
        throw AuthError.EmailMissingInSltContext()
      }

      // Xác thực OTP
      const isValid = await this.otpService.verifyOTP(
        email,
        otpCode,
        sltContext.purpose,
        sltContext.userId,
        ipAddress,
        userAgent
      )

      if (!isValid) {
        throw AuthError.InvalidOTP()
      }

      // Finalize SLT
      await this.sltService.finalizeSlt(sltContext.sltJti)

      return sltContext
    } catch (error) {
      this.logger.error(`[verifyWithOTP] Error: ${error.message}`, error.stack)
      if (error instanceof AuthError) throw error
      throw AuthError.InvalidOTP()
    }
  }

  /**
   * Xác thực bằng 2FA
   */
  private async verifyWith2FA(
    sltContext: SltContextData & { sltJti: string },
    code: string,
    method: string,
    ipAddress: string,
    userAgent: string,
    rememberMe: boolean
  ): Promise<any> {
    try {
      // Xác minh 2FA
      const verificationResult = await this.twoFactorService.verifyTwoFactor(
        code,
        rememberMe,
        sltContext.sltJti,
        ipAddress,
        userAgent,
        method
      )

      return verificationResult
    } catch (error) {
      this.logger.error(`[verifyWith2FA] Error: ${error.message}`, error.stack)
      if (error instanceof AuthError) throw error
      throw AuthError.InvalidTOTP()
    }
  }

  /**
   * Xử lý các hành động sau khi xác thực thành công
   */
  private async handlePostVerificationActions(
    sltContext: SltContextData & { sltJti: string },
    verificationResult: any,
    ipAddress: string,
    userAgent: string,
    res: Response
  ): Promise<VerificationResult> {
    const purpose = sltContext.purpose as TypeOfVerificationCode
    const rememberMe = sltContext.metadata?.rememberMe === true

    // Đảm bảo SLT được finalize nếu nó đến từ luồng 2FA và twoFactorService chưa finalize
    // Đối với OTP, nó đã được finalize trong verifyWithOTP
    if (this.shouldUse2FAForPurpose(purpose) && sltContext.finalized !== '1') {
      const is2FAVerificationSuccessful = verificationResult && verificationResult.success
      if (is2FAVerificationSuccessful || verificationResult.user) {
        await this.sltService.finalizeSlt(sltContext.sltJti)
        this.logger.debug(
          `[handlePostVerificationActions] SLT ${sltContext.sltJti} finalized for 2FA purpose: ${purpose}`
        )
      } else if (
        !is2FAVerificationSuccessful &&
        !verificationResult.user &&
        purpose === TypeOfVerificationCode.LOGIN_UNTRUSTED_DEVICE_2FA
      ) {
        this.logger.warn(
          `[handlePostVerificationActions] 2FA verification failed for login purpose ${purpose}. SLT ${sltContext.sltJti} not finalized yet.`
        )
      }
    }

    // Xử lý theo loại hành động
    switch (purpose) {
      case TypeOfVerificationCode.LOGIN:
      case TypeOfVerificationCode.LOGIN_UNTRUSTED_DEVICE_OTP:
      case TypeOfVerificationCode.LOGIN_UNTRUSTED_DEVICE_2FA:
        return this.handleLoginVerification(sltContext, verificationResult, ipAddress, userAgent, res, rememberMe)

      case TypeOfVerificationCode.REVOKE_SESSIONS:
      case TypeOfVerificationCode.REVOKE_SESSIONS_2FA:
        return this.handleRevokeSessionsVerification(sltContext, verificationResult, ipAddress, userAgent, res)

      case TypeOfVerificationCode.REVOKE_ALL_SESSIONS:
      case TypeOfVerificationCode.REVOKE_ALL_SESSIONS_2FA:
        return this.handleRevokeAllSessionsVerification(sltContext, verificationResult, ipAddress, userAgent, res)

      case TypeOfVerificationCode.UNLINK_GOOGLE_ACCOUNT:
        return this.handleUnlinkGoogleAccountVerification(sltContext, verificationResult, ipAddress, userAgent, res)

      case TypeOfVerificationCode.DISABLE_2FA:
        return this.handleDisable2FAVerification(sltContext, verificationResult, ipAddress, userAgent, res)

      case TypeOfVerificationCode.REGISTER:
        return this.handleRegisterVerification(sltContext, verificationResult, ipAddress, userAgent, res)

      default:
        this.logger.warn(
          `[handlePostVerificationActions] Unhandled purpose: ${purpose}. Finalizing SLT ${sltContext.sltJti} as a fallback.`
        )
        if (sltContext.finalized !== '1') await this.sltService.finalizeSlt(sltContext.sltJti)
        return {
          success: true,
          message: 'Xác thực thành công cho mục đích không xác định.',
          sltContext
        }
    }
  }

  /**
   * Xử lý xác thực đăng nhập
   */
  private async handleLoginVerification(
    sltContext: SltContextData & { sltJti: string },
    verificationResult: any,
    ipAddress: string,
    userAgent: string,
    res: Response,
    rememberMe: boolean
  ): Promise<VerificationResult> {
    try {
      // SLT đã được finalize trong verifyWithOTP hoặc trong handlePostVerificationActions (cho 2FA)
      // Không cần finalize lại ở đây trừ khi có logic cụ thể yêu cầu.
      this.logger.debug(
        `[handleLoginVerification] Finalizing login for user ${sltContext.userId}, device ${sltContext.deviceId}, rememberMe: ${rememberMe}`
      )

      const loginResult = await this.coreService.finalizeLoginAfterVerification(
        sltContext.userId,
        sltContext.deviceId,
        rememberMe,
        res,
        ipAddress,
        userAgent
      )

      return {
        success: true,
        message: loginResult.message || this.i18nService.t('auth.Auth.Login.Success'),
        tokens: {
          accessToken: loginResult.accessToken,
          refreshToken: loginResult.refreshToken
        },
        user: loginResult.user
      }
    } catch (error) {
      this.logger.error(`[handleLoginVerification] Error: ${error.message}`, error.stack)
      // Không clear SLT cookie ở đây để user có thể thử lại nếu lỗi là tạm thời
      // Trừ khi lỗi chỉ ra SLT không hợp lệ
      if (error instanceof AuthError) throw error
      throw AuthError.InternalServerError()
    }
  }

  /**
   * Xử lý xác thực thu hồi session cụ thể
   */
  private async handleRevokeSessionsVerification(
    sltContext: SltContextData & { sltJti: string },
    verificationPayload: any,
    ipAddress: string,
    userAgent: string,
    res: Response
  ): Promise<VerificationResult> {
    try {
      // Đảm bảo SLT đã được finalized
      if (sltContext.finalized !== '1') {
        await this.sltService.finalizeSlt(sltContext.sltJti)
      }

      // Xử lý danh sách session cần thu hồi từ metadata
      const sessionIdsToRevoke = sltContext.metadata?.sessionIds
      const deviceIdsToRevoke = sltContext.metadata?.deviceIds

      if (!sessionIdsToRevoke && !deviceIdsToRevoke) {
        throw AuthError.InsufficientRevocationData()
      }

      // Thu hồi các session sử dụng SessionsService
      const revokeResult = await this.sessionsService.revokeItems(
        sltContext.userId,
        {
          sessionIds: sessionIdsToRevoke,
          deviceIds: deviceIdsToRevoke,
          excludeCurrentSession: sltContext.metadata?.excludeCurrentSession
        },
        {
          sessionId: sltContext.metadata?.currentSessionId,
          deviceId: sltContext.metadata?.currentDeviceId
        },
        undefined, // Không cần token vì đã xác thực
        undefined, // Không cần OTP vì đã xác thực
        ipAddress,
        userAgent
      )

      return {
        success: true,
        message: revokeResult.message || this.i18nService.t('auth.Auth.Session.RevokedSuccessfully')
      }
    } catch (error) {
      this.logger.error(`[handleRevokeSessionsVerification] Error: ${error.message}`, error.stack)
      if (error instanceof AuthError) throw error
      throw AuthError.InternalServerError()
    }
  }

  /**
   * Xử lý xác thực thu hồi tất cả session
   */
  private async handleRevokeAllSessionsVerification(
    sltContext: SltContextData & { sltJti: string },
    verificationPayload: any,
    ipAddress: string,
    userAgent: string,
    res: Response
  ): Promise<VerificationResult> {
    try {
      // Đảm bảo SLT đã được finalized
      if (sltContext.finalized !== '1') {
        await this.sltService.finalizeSlt(sltContext.sltJti)
      }

      // Thu hồi tất cả session sử dụng SessionsService
      const revokeResult = await this.sessionsService.revokeItems(
        sltContext.userId,
        {
          revokeAllUserSessions: true,
          excludeCurrentSession: sltContext.metadata?.excludeCurrentSession
        },
        {
          sessionId: sltContext.metadata?.currentSessionId,
          deviceId: sltContext.deviceId
        },
        undefined, // Không cần token vì đã xác thực
        undefined, // Không cần OTP vì đã xác thực
        ipAddress,
        userAgent
      )

      return {
        success: true,
        message: revokeResult.message || this.i18nService.t('auth.Auth.Session.AllRevoked')
      }
    } catch (error) {
      this.logger.error(`[handleRevokeAllSessionsVerification] Error: ${error.message}`, error.stack)
      if (error instanceof AuthError) throw error
      throw AuthError.InternalServerError()
    }
  }

  /**
   * Xử lý xác thực hủy liên kết Google
   */
  private async handleUnlinkGoogleAccountVerification(
    sltContext: SltContextData & { sltJti: string },
    verificationPayload: any,
    ipAddress: string,
    userAgent: string,
    res: Response
  ): Promise<VerificationResult> {
    try {
      // Đảm bảo SLT đã được finalized
      if (sltContext.finalized !== '1') {
        await this.sltService.finalizeSlt(sltContext.sltJti)
      }

      // Thực hiện hủy liên kết Google
      const result = await this.socialService.verifyAndUnlinkGoogleAccount(sltContext.userId, sltContext.sltJti)

      return {
        success: true,
        message: result.message || 'Đã hủy liên kết tài khoản Google thành công'
      }
    } catch (error) {
      this.logger.error(`[handleUnlinkGoogleAccountVerification] Error: ${error.message}`, error.stack)
      if (error instanceof AuthError) throw error
      throw AuthError.InternalServerError()
    }
  }

  /**
   * Xử lý xác thực tắt 2FA
   */
  private async handleDisable2FAVerification(
    sltContext: SltContextData & { sltJti: string },
    verificationPayload: any,
    ipAddress: string,
    userAgent: string,
    res: Response
  ): Promise<VerificationResult> {
    try {
      // Đảm bảo SLT đã được finalized
      if (sltContext.finalized !== '1') {
        await this.sltService.finalizeSlt(sltContext.sltJti)
      }

      // Tắt xác thực hai yếu tố
      await this.twoFactorService.disableVerification(sltContext.userId)

      return {
        success: true,
        message: this.i18nService.t('auth.Auth.2FA.Disable.Success')
      }
    } catch (error) {
      this.logger.error(`[handleDisable2FAVerification] Error: ${error.message}`, error.stack)
      if (error instanceof AuthError) throw error
      throw AuthError.InternalServerError()
    }
  }

  /**
   * Xử lý xác thực đăng ký
   */
  private async handleRegisterVerification(
    sltContext: SltContextData & { sltJti: string },
    verificationPayload: any,
    ipAddress: string,
    userAgent: string,
    res: Response
  ): Promise<VerificationResult> {
    try {
      // Đảm bảo SLT đã được finalized
      if (sltContext.finalized !== '1') {
        await this.sltService.finalizeSlt(sltContext.sltJti)
      }

      return {
        success: true,
        message: this.i18nService.t('auth.Auth.Register.EmailSent'),
        sltContext
      }
    } catch (error) {
      this.logger.error(`[handleRegisterVerification] Error: ${error.message}`, error.stack)
      if (error instanceof AuthError) throw error
      throw AuthError.InternalServerError()
    }
  }
}
