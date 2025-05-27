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
      throw InvalidRefreshTokenException // Throw standard exception
    }
  }

  async generateTokens(payload: AccessTokenPayloadCreate, _prismaTx?: any, rememberMe?: boolean) {
    return this.tokenService.generateTokens(payload, _prismaTx, rememberMe)
  }

  // async logoutFromAllDevices( // Bắt đầu comment hoặc xóa
  //   activeUser: AccessTokenPayload,
  //   ip: string,
  //   userAgent: string,
  //   _req: Request, // _req is not used in the new logic
  //   res: Response
  // ) {
  //   this.logger.log(
  //     `User ${activeUser.userId} requesting logout from all devices. Current session: ${activeUser.sessionId}, Device: ${activeUser.deviceId}`
  //   )
  //   const auditLogEntry: Partial<AuditLogData> & { details: Prisma.JsonObject } = {
  //     action: 'USER_LOGOUT_ALL_ATTEMPT',
  //     userId: activeUser.userId,
  //     ipAddress: ip,
  //     userAgent: userAgent,
  //     status: AuditLogStatus.FAILURE,
  //     details: {
  //       currentSessionId: activeUser.sessionId,
  //       currentDeviceId: activeUser.deviceId
  //     }
  //   }

  //   try {
  //     // Invalidate all sessions for the user EXCEPT the current one.
  //     const { invalidatedCount } = await this.tokenService.invalidateAllUserSessions(
  //       activeUser.userId,
  //       'USER_REQUEST_LOGOUT_ALL',
  //       activeUser.sessionId // Exclude current session from invalidation
  //     )

  //     // Deactivate and untrust all other devices for the user
  //     // This step needs careful consideration if the current device should also be untrusted/deactivated.
  //     // For a typical "logout all others", the current device remains active and trusted.
  //     // If the intent is to also untrust the current device and force re-auth, that needs to be explicit.
  //     const deactivatedDevicesCount = await this.deviceService.deactivateAndUntrustAllUserDevices(
  //       activeUser.userId,
  //       activeUser.deviceId // Exclude current device
  //     )

  //     // Cookies for the current session are NOT cleared here because the current session remains active.
  //     // The client is expected to still have its valid refresh/access tokens for the current session.

  //     auditLogEntry.status = AuditLogStatus.SUCCESS
  //     auditLogEntry.action = 'USER_LOGOUT_ALL_SUCCESS'
  //     auditLogEntry.details.sessionsInvalidated = invalidatedCount
  //     auditLogEntry.details.devicesDeactivatedAndUntrusted = deactivatedDevicesCount

  //     await this.auditLogService.record(auditLogEntry as AuditLogData)

  //     const message = await this.i18nService.translate('Auth.LogoutAll.Success', {
  //       lang: I18nContext.current()?.lang,
  //       args: { count: invalidatedCount }
  //     })
  //     return { message }
  //   } catch (error) {
  //     this.logger.error(`Error during logout from all devices for user ${activeUser.userId}:`, error)
  //     auditLogEntry.errorMessage = error instanceof Error ? error.message : 'Unknown error'
  //     await this.auditLogService.record(auditLogEntry as AuditLogData)
  //     throw error // Re-throw the error to be handled by global exception filter
  //   }
  // } // Kết thúc comment hoặc xóa

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
        return this.twoFactorAuthService.verifyTwoFactor(body, sltContext, res)
      } else if (sltContext.purpose === TypeOfVerificationCode.LOGIN_UNTRUSTED_DEVICE_OTP) {
        this.logger.debug(
          '[AuthService verifyTwoFactor] SLT purpose is LOGIN_UNTRUSTED_DEVICE_OTP. Proceeding with untrusted device OTP login completion.'
        )
        return this.authenticationService.completeLoginWithUntrustedDeviceOtp(body, sltContext, res)
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
        error.stack // Log stack for better debugging
      )

      let shouldClearSltCookie = true // Default to clearing cookie on error
      let shouldFinalizeSlt = true // Default to finalizing SLT if context exists

      if (error instanceof ApiException) {
        // Convert non-string responses to string for consistent errorCode checking
        const errorResponse = error.getResponse()
        let errorCode = ''
        if (typeof errorResponse === 'string') {
          errorCode = errorResponse
        } else if (typeof errorResponse === 'object' && errorResponse !== null && 'errorCode' in errorResponse) {
          errorCode = (errorResponse as any).errorCode
        } else if (typeof errorResponse === 'object' && errorResponse !== null && 'message' in errorResponse) {
          // Fallback for cases where errorCode might not be the primary field
          errorCode = (errorResponse as any).message
        }

        this.logger.debug(`[AuthService verifyTwoFactor] Caught ApiException with errorCode: ${errorCode}`)

        if (
          errorCode === 'Error.Auth.Otp.Invalid' ||
          errorCode === 'Error.Auth.2FA.InvalidTOTP' ||
          errorCode === 'Error.Auth.2FA.InvalidRecoveryCode'
        ) {
          // These are errors where the user might still have attempts left with the current SLT.
          shouldClearSltCookie = false
          shouldFinalizeSlt = false // Don't finalize if they can retry with this SLT
          this.logger.debug(
            `[AuthService verifyTwoFactor] সিদ্ধান্ত নেওয়া হয়েছে SLT কুকি সাফ বা চূড়ান্ত না করার জন্য: ${errorCode}`
          )
        } else if (errorCode === 'Error.Auth.Verification.MaxAttemptsExceeded') {
          // SLT should have been finalized by the service that threw this.
          // Cookie should be cleared. Finalization already done by the thrower.
          shouldFinalizeSlt = false
          this.logger.debug(
            `[AuthService verifyTwoFactor] Max attempts exceeded, SLT কুকি সাফ করা হবে, SLT ইতিমধ্যে চূড়ান্ত করা হয়েছে৷`
          )
        } else {
          this.logger.debug(
            `[AuthService verifyTwoFactor] ডিফল্ট আচরণ: SLT কুকি সাফ এবং চূড়ান্ত করা হবে ত্রুটির জন্য: ${errorCode}`
          )
        }
      } else {
        this.logger.debug(
          `[AuthService verifyTwoFactor] Non-ApiException error. Defaulting to clearing/finalizing SLT if context exists.`
        )
      }

      if (shouldFinalizeSlt && sltContext && sltContext.sltJti) {
        try {
          this.logger.warn(`[AuthService] Finalizing SLT JTI ${sltContext.sltJti} due to error: ${error.message}`)
          await this.otpService.finalizeSlt(sltContext.sltJti)
        } catch (finalizeError) {
          this.logger.error(
            `[AuthService] Error finalizing SLT JTI ${sltContext.sltJti} during error handling: ${finalizeError.message}`
          )
        }
      }

      if (shouldClearSltCookie && res) {
        this.tokenService.clearSltCookie(res)
        this.logger.debug('[AuthService verifyTwoFactor] SLT cookie cleared based on error type.')
      }
      throw error // Re-throw the original error
    }
  }
}
