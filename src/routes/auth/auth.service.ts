import { Injectable, Logger } from '@nestjs/common'
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
import { InvalidRefreshTokenException } from 'src/routes/auth/auth.error'
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
import { HttpStatus } from '@nestjs/common'
import { TypeOfVerificationCode } from './constants/auth.constants'

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
      return { message, error: 'RefreshFailed' } // Or throw new UnauthorizedException(message)
    }
  }

  async generateTokens(payload: AccessTokenPayloadCreate, _prismaTx?: any, rememberMe?: boolean) {
    return this.tokenService.generateTokens(payload, _prismaTx, rememberMe)
  }

  async logoutFromAllDevices(
    activeUser: AccessTokenPayload,
    ip: string,
    userAgent: string,
    _req: Request, // _req is not used in the new logic
    res: Response
  ) {
    const auditLogEntry: Partial<AuditLogData> = {
      action: 'LOGOUT_ALL_DEVICES_ATTEMPT',
      userId: activeUser.userId,
      ipAddress: ip,
      userAgent,
      status: AuditLogStatus.FAILURE,
      details: {
        currentSessionId: activeUser.sessionId,
        currentDeviceId: activeUser.deviceId
      } as Prisma.JsonObject
    }

    try {
      // Invalidate all other sessions for this user
      // The reason 'USER_REQUEST_LOGOUT_ALL_EXCLUDING_CURRENT' implies that the current session might be handled differently or next.
      await this.tokenService.invalidateAllUserSessions(activeUser.userId, 'USER_REQUEST_LOGOUT_ALL_EXCLUDING_CURRENT')

      // Now, invalidate the current session and clear cookies for the user initiating the action
      await this.tokenService.invalidateSession(activeUser.sessionId, 'CURRENT_SESSION_LOGOUT_AFTER_LOGOUT_ALL')
      this.tokenService.clearTokenCookies(res)

      auditLogEntry.status = AuditLogStatus.SUCCESS
      auditLogEntry.action = 'LOGOUT_ALL_DEVICES_SUCCESS'
      await this.auditLogService.record(auditLogEntry as AuditLogData)

      const message = await this.i18nService.translate('error.Auth.Logout.AllDevicesSuccess', {
        lang: I18nContext.current()?.lang
      })
      return { message }
    } catch (error) {
      auditLogEntry.errorMessage = error instanceof Error ? error.message : String(error)
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      // Clear cookies even on error as a safety measure
      this.tokenService.clearTokenCookies(res)
      throw error
    }
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
      throw new ApiException(HttpStatus.BAD_REQUEST, 'ValidationError', 'Error.Auth.OtpToken.Invalid')
    }

    let sltContext: (SltContextData & { sltJti: string }) | null = null
    try {
      // Validate SLT without expected purpose first to get the actual purpose
      sltContext = await this.otpService.validateSltFromCookieAndGetContext(
        body.sltCookie,
        body.ip,
        body.userAgent
        // No expectedPurpose initially
      )

      this.logger.debug(
        `[AuthService verifyTwoFactor] SLT context validated. Purpose: ${sltContext.purpose}, UserID: ${sltContext.userId}`
      )

      if (sltContext.purpose === TypeOfVerificationCode.LOGIN_2FA) {
        this.logger.debug('[AuthService verifyTwoFactor] SLT purpose is LOGIN_2FA. Proceeding with 2FA verification.')
        return this.twoFactorAuthService.verifyTwoFactor(body, res)
      } else if (sltContext.purpose === TypeOfVerificationCode.LOGIN_UNTRUSTED_DEVICE_OTP) {
        this.logger.debug(
          '[AuthService verifyTwoFactor] SLT purpose is LOGIN_UNTRUSTED_DEVICE_OTP. Proceeding with untrusted device OTP login completion.'
        )
        return this.authenticationService.completeLoginWithUntrustedDeviceOtp(body, res)
      } else {
        this.logger.error(
          `[AuthService verifyTwoFactor] Invalid SLT purpose: ${sltContext.purpose} for JTI: ${sltContext.sltJti}. Expected LOGIN_2FA or LOGIN_UNTRUSTED_DEVICE_OTP.`
        )
        await this.otpService.finalizeSlt(sltContext.sltJti) // Finalize unexpected SLT
        if (res) this.tokenService.clearSltCookie(res) // Clear the cookie

        this.auditLogService.recordAsync({
          action: 'VERIFY_2FA_OR_OTP_FAIL',
          status: AuditLogStatus.FAILURE,
          userId: sltContext.userId,
          userEmail: sltContext.email,
          ipAddress: body.ip,
          userAgent: body.userAgent,
          errorMessage: 'INVALID_SLT_PURPOSE_FOR_VERIFICATION_ENDPOINT',
          details: {
            sltJti: sltContext.sltJti,
            actualPurpose: sltContext.purpose,
            expectedPurposes: [TypeOfVerificationCode.LOGIN_2FA, TypeOfVerificationCode.LOGIN_UNTRUSTED_DEVICE_OTP]
          } as Prisma.JsonObject
        })
        throw new ApiException(HttpStatus.BAD_REQUEST, 'ValidationError', 'Error.Auth.Session.InvalidLogin')
      }
    } catch (error) {
      this.logger.error(
        `[AuthService verifyTwoFactor] Error during SLT validation or processing: ${error.message}`,
        error
      )
      // If SLT context was fetched and an error occurred AFTERWARDS, and it wasn't finalized by the downstream service
      // (e.g. if the error is from validateSltFromCookieAndGetContext itself, it won't be finalized there)
      // However, downstream services (verifyTwoFactor, completeLoginWithUntrustedDeviceOtp) ARE responsible for finalizing SLT on their success/failure paths.
      // This catch block is more for errors directly from validateSltFromCookieAndGetContext or unexpected errors before routing.
      if (sltContext && sltContext.sltJti) {
        // Check if the error indicates the context might still be active
        // For example, if the error is NOT that the context is already finalized or not found
        if (error instanceof ApiException) {
          const apiErrorResponse = error.getResponse()
          if (typeof apiErrorResponse === 'object' && apiErrorResponse !== null) {
            const message = (apiErrorResponse as any).message
            if (
              message !== 'SLT_CONTEXT_ALREADY_FINALIZED' &&
              message !== 'SLT_CONTEXT_NOT_FOUND_OR_EXPIRED_IN_REDIS'
            ) {
              // Potentially finalize and clear cookie if it's an unexpected error path
              // that might leave the SLT active.
              // However, this is risky as the error might be transient. It's safer to let it expire.
              // this.logger.debug(`[AuthService verifyTwoFactor] Considering SLT finalization due to error: ${error.message}`);
            }
          }
        }
      }
      if (res) {
        this.tokenService.clearSltCookie(res) // Clear SLT cookie on any error from this top-level handler
        this.logger.debug('[AuthService verifyTwoFactor] SLT cookie cleared due to error in verifyTwoFactor.')
      }
      throw error // Re-throw the original error
    }
  }
}
