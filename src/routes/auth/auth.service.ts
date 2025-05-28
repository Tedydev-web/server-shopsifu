import { Injectable, Logger, HttpStatus } from '@nestjs/common'
import {
  DisableTwoFactorBodyType,
  LoginBodyType,
  RegisterBodyType,
  ResetPasswordBodyType,
  SendOTPBodyType,
  TwoFactorVerifyBodyType,
  VerifyCodeBodyType
} from 'src/routes/auth/auth.model'
import { AuthRepository } from 'src/routes/auth/auth.repo'
import { RolesService } from 'src/routes/auth/roles.service'
import { SharedUserRepository } from './repositories/shared-user.repo'
import { HashingService } from 'src/shared/services/hashing.service'
import { TokenService } from 'src/routes/auth/providers/token.service'
import { EmailService } from 'src/routes/auth/providers/email.service'
import { AccessTokenPayload, AccessTokenPayloadCreate } from 'src/shared/types/jwt.type'
import {
  InvalidRefreshTokenException,
  InvalidOTPException,
  InvalidTOTPException,
  InvalidRecoveryCodeException,
  MaxVerificationAttemptsExceededException,
  SltCookieMissingException,
  SltContextFinalizedException,
  SltContextMaxAttemptsReachedException,
  DeviceMismatchException
} from 'src/routes/auth/auth.error'
import { TwoFactorService } from 'src/routes/auth/providers/2fa.service'
import { Response, Request } from 'express'
import { PrismaService } from 'src/shared/services/prisma.service'
import { AuditLogService, AuditLogData, AuditLogStatus } from '../audit-log/audit-log.service'
import { OtpService, SltContextData } from 'src/routes/auth/providers/otp.service'
import { DeviceService } from 'src/routes/auth/providers/device.service'
import { AuthenticationService } from './services/authentication.service'
import { TwoFactorAuthService } from './services/two-factor-auth.service'
import { OtpAuthService } from './services/otp-auth.service'
import { PasswordAuthService } from './services/password-auth.service'
import envConfig from 'src/shared/config'
import { I18nService, I18nContext } from 'nestjs-i18n'
import { Prisma } from '@prisma/client'
import { ApiException } from 'src/shared/exceptions/api.exception'
import { TypeOfVerificationCode, MAX_SLT_ATTEMPTS } from './constants/auth.constants'

@Injectable()
export class AuthService {
  constructor(
    private readonly prismaService: PrismaService,
    private readonly hashingService: HashingService,
    private readonly rolesService: RolesService,
    private readonly authRepository: AuthRepository,
    private readonly sharedUserRepository: SharedUserRepository,
    private readonly emailService: EmailService,
    private readonly tokenService: TokenService,
    private readonly twoFactorService: TwoFactorService,
    private readonly auditLogService: AuditLogService,
    private readonly otpService: OtpService,
    private readonly deviceService: DeviceService,
    private readonly authenticationService: AuthenticationService,
    private readonly twoFactorAuthService: TwoFactorAuthService,
    private readonly otpAuthService: OtpAuthService,
    private readonly passwordAuthService: PasswordAuthService,
    private readonly i18nService: I18nService
  ) {}

  private readonly logger = new Logger(AuthService.name)

  async verifyCode(body: VerifyCodeBodyType & { userAgent: string; ip: string }) {
    return this.otpAuthService.verifyCode(body)
  }

  async sendOTP(body: SendOTPBodyType) {
    return this.otpAuthService.sendOTP(body)
  }

  async register(body: RegisterBodyType & { userAgent?: string; ip?: string }) {
    return this.authenticationService.register(body)
  }

  async login(body: LoginBodyType & { userAgent: string; ip: string }, res?: Response) {
    return this.authenticationService.login(body, res)
  }

  async logout(req: Request, res: Response) {
    return this.authenticationService.logout(req, res)
  }

  async refreshToken({ userAgent, ip }: { userAgent: string; ip: string }, req: Request, res?: Response) {
    this.logger.debug(`Refresh token request from IP: ${ip}, User-Agent: ${userAgent}`)

    const refreshTokenFromCookie = this.tokenService.extractRefreshTokenFromRequest(req)

    if (!refreshTokenFromCookie) {
      this.logger.warn('Refresh token not found in request for silent refresh.')
      // Consider throwing an error or returning a specific response if no refresh token
      // For now, relying on tokenService.refreshTokenSilently to handle this implicitly
    }

    const result = await this.tokenService.refreshTokenSilently(refreshTokenFromCookie || '', userAgent, ip)

    if (result && result.accessToken && res) {
      this.tokenService.setTokenCookies(
        res,
        result.accessToken,
        result.refreshToken || '',
        result.maxAgeForRefreshTokenCookie
      )
      const message = await this.i18nService.translate('Auth.Token.Refreshed', {
        lang: I18nContext.current()?.lang
      })
      return { message, accessToken: result.accessToken }
    } else {
      // If refresh failed, ensure cookies are cleared if res is available
      if (res) {
        this.tokenService.clearTokenCookies(res)
      }
      const message = await this.i18nService.translate('Error.Auth.Token.RefreshFailed', {
        lang: I18nContext.current()?.lang
      })
      // Consider throwing an appropriate HTTP exception here, e.g., UnauthorizedException
      throw InvalidRefreshTokenException // Throw standard exception
    }
  }

  async generateTokens(payload: AccessTokenPayloadCreate, _prismaTx?: any, rememberMe?: boolean) {
    return this.tokenService.generateTokens(payload, _prismaTx, rememberMe)
  }

  async setRememberMe(
    activeUser: AccessTokenPayload,
    rememberMe: boolean,
    req: Request,
    res: Response,
    ip: string,
    userAgent: string
  ) {
    return this.authenticationService.setRememberMe(activeUser, rememberMe, req, res, ip, userAgent)
  }

  async resetPassword(body: ResetPasswordBodyType & { userAgent?: string; ip?: string }) {
    return this.passwordAuthService.resetPassword(body)
  }

  async changePassword(userId: number, currentPassword: string, newPassword: string, ip?: string, userAgent?: string) {
    return this.passwordAuthService.changePassword(userId, currentPassword, newPassword, ip, userAgent)
  }

  async setupTwoFactorAuth(userId: number) {
    return this.twoFactorAuthService.setupTwoFactorAuth(userId)
  }

  async confirmTwoFactorSetup(userId: number, setupToken: string, totpCode: string) {
    return this.twoFactorAuthService.confirmTwoFactorSetup(userId, setupToken, totpCode)
  }

  async disableTwoFactorAuth(data: DisableTwoFactorBodyType & { userId: number; userAgent?: string; ip?: string }) {
    return this.twoFactorAuthService.disableTwoFactorAuth(data)
  }

  async verifyTwoFactor(
    body: TwoFactorVerifyBodyType & { userAgent: string; ip: string; sltCookie?: string },
    res?: Response
  ) {
    this.logger.debug(
      `[AuthService] verifyTwoFactor called. Email: ${body.email}, Code: ${body.code ? '******' : undefined}, RecoveryCode: ${body.recoveryCode ? '******' : undefined}, SLTCookie Provided: ${!!body.sltCookie}`
    )

    if (!body.sltCookie) {
      this.logger.warn('[AuthService verifyTwoFactor] SLT cookie is missing.')
      this.auditLogService.recordAsync({
        action: 'VERIFY_2FA_OR_OTP_FAIL',
        status: AuditLogStatus.FAILURE,
        userEmail: body.email,
        ipAddress: body.ip,
        userAgent: body.userAgent,
        errorMessage: 'MISSING_SLT_COOKIE',
        details: { codeProvided: !!body.code, recoveryCodeProvided: !!body.recoveryCode } as Prisma.JsonObject
      })
      throw SltCookieMissingException
    }

    let sltContext: (SltContextData & { sltJti: string }) | null = null
    try {
      sltContext = await this.otpService.validateSltFromCookieAndGetContext(body.sltCookie, body.ip, body.userAgent)

      this.logger.debug(
        `[AuthService verifyTwoFactor] SLT context validated. Purpose: ${sltContext.purpose}, UserID: ${sltContext.userId}, Attempts: ${sltContext.attempts}`
      )

      if (sltContext.finalized === '1') {
        this.logger.warn(`[AuthService verifyTwoFactor] SLT JTI ${sltContext.sltJti} is already finalized.`)
        if (res) this.tokenService.clearSltCookie(res)
        throw SltContextFinalizedException
      }

      if (sltContext.attempts >= MAX_SLT_ATTEMPTS) {
        this.logger.warn(
          `[AuthService verifyTwoFactor] SLT JTI ${sltContext.sltJti} has reached max attempts (${sltContext.attempts}/${MAX_SLT_ATTEMPTS}).`
        )
        await this.otpService.finalizeSlt(sltContext.sltJti)
        if (res) this.tokenService.clearSltCookie(res)
        throw SltContextMaxAttemptsReachedException
      }

      if (sltContext.purpose === TypeOfVerificationCode.LOGIN_2FA) {
        this.logger.debug('[AuthService verifyTwoFactor] SLT purpose is LOGIN_2FA. Proceeding with 2FA verification.')
        return await this.twoFactorAuthService.verifyTwoFactor(body, sltContext, res)
      } else if (sltContext.purpose === TypeOfVerificationCode.LOGIN_UNTRUSTED_DEVICE_OTP) {
        this.logger.debug(
          '[AuthService verifyTwoFactor] SLT purpose is LOGIN_UNTRUSTED_DEVICE_OTP. Proceeding with untrusted device OTP login completion.'
        )
        if (!body.code) {
          throw new ApiException(HttpStatus.BAD_REQUEST, 'ValidationError', 'Error.Auth.Otp.CodeRequired', [
            { code: 'Error.Auth.Otp.CodeRequired', path: 'code' }
          ])
        }
        return await this.authenticationService.completeLoginWithUntrustedDeviceOtp(body, sltContext, res)
      } else if (sltContext.purpose === TypeOfVerificationCode.REVERIFY_SESSION_OTP) {
        this.logger.debug(
          '[AuthService verifyTwoFactor] SLT purpose is REVERIFY_SESSION_OTP. Proceeding with session OTP reverification.'
        )
        if (!body.code) {
          throw new ApiException(HttpStatus.BAD_REQUEST, 'ValidationError', 'Error.Auth.Otp.CodeRequired', [
            { code: 'Error.Auth.Otp.CodeRequired', path: 'code' }
          ])
        }
        throw new ApiException(
          HttpStatus.NOT_IMPLEMENTED,
          'NotImplemented',
          'Reverify session OTP via SLT not fully implemented here.'
        )
      } else {
        this.logger.error(
          `[AuthService verifyTwoFactor] Unknown SLT purpose: ${sltContext.purpose} for JTI ${sltContext.sltJti}`
        )
        await this.otpService.finalizeSlt(sltContext.sltJti)
        if (res) this.tokenService.clearSltCookie(res)
        throw new ApiException(HttpStatus.BAD_REQUEST, 'ValidationError', 'Error.Auth.OtpToken.Invalid')
      }
    } catch (error) {
      this.logger.error(
        `[AuthService verifyTwoFactor] Error during SLT validation or processing. SLT JTI: ${sltContext?.sltJti || 'N/A'}`,
        error.stack
      )

      const thrownErrorCode = error instanceof ApiException ? error.errorCode : null

      const isVerificationCodeError =
        thrownErrorCode === InvalidOTPException.errorCode ||
        thrownErrorCode === InvalidTOTPException.errorCode ||
        thrownErrorCode === InvalidRecoveryCodeException.errorCode

      if (sltContext && isVerificationCodeError) {
        this.logger.warn(
          `[AuthService verifyTwoFactor] Verification code error for SLT JTI ${sltContext.sltJti}. Incrementing attempts.`
        )
        try {
          const newAttempts = await this.otpService.incrementSltAttempts(sltContext.sltJti)
          this.auditLogService.recordAsync({
            userId: sltContext.userId,
            action: 'VERIFY_2FA_OR_OTP_CODE_INVALID_ATTEMPT',
            status: AuditLogStatus.FAILURE,
            ipAddress: sltContext.ipAddress,
            userAgent: sltContext.userAgent,
            errorMessage: error.message,
            details: {
              sltJti: sltContext.sltJti,
              purpose: sltContext.purpose,
              currentAttempts: newAttempts,
              maxAttempts: MAX_SLT_ATTEMPTS,
              originalErrorCode: thrownErrorCode,
              originalErrorMessageFromApiException: error.message
            } as Prisma.JsonObject
          })

          if (newAttempts >= MAX_SLT_ATTEMPTS) {
            this.logger.warn(
              `[AuthService verifyTwoFactor] Max attempts reached for SLT JTI ${sltContext.sltJti} after failed attempt. Finalizing and clearing cookie.`
            )
            await this.otpService.finalizeSlt(sltContext.sltJti)
            if (res) this.tokenService.clearSltCookie(res)
            throw MaxVerificationAttemptsExceededException
          }
        } catch (incrementError) {
          this.logger.error(
            `[AuthService verifyTwoFactor] Error during SLT attempt increment/finalization for JTI ${sltContext.sltJti}: ${incrementError.message}`
          )
          if (res) this.tokenService.clearSltCookie(res)
          throw incrementError
        }
        throw error
      } else {
        if (sltContext?.sltJti) {
          if (
            thrownErrorCode !== MaxVerificationAttemptsExceededException.errorCode &&
            thrownErrorCode !== SltContextFinalizedException.errorCode &&
            thrownErrorCode !== SltContextMaxAttemptsReachedException.errorCode &&
            thrownErrorCode !== DeviceMismatchException.errorCode
          ) {
            await this.otpService.finalizeSlt(sltContext.sltJti)
          }
        }
        if (res) this.tokenService.clearSltCookie(res)

        if (thrownErrorCode === DeviceMismatchException.errorCode) {
          this.logger.warn(
            `[AuthService verifyTwoFactor] SLT DeviceMismatchException for JTI ${sltContext?.sltJti}. SLT should have been finalized by OtpService. Cookie cleared.`
          )
          throw error
        }

        if (error instanceof ApiException) throw error
        throw new ApiException(
          HttpStatus.INTERNAL_SERVER_ERROR,
          'ServerError',
          'Error.Global.InternalServerError',
          error
        )
      }
    }
  }
}
