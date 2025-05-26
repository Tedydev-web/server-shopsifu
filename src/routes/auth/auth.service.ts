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
import { OtpService } from 'src/routes/auth/providers/otp.service'
import { DeviceService } from 'src/routes/auth/providers/device.service'
import { AuthenticationService } from './services/authentication.service'
import { TwoFactorAuthService } from './services/two-factor-auth.service'
import { OtpAuthService } from './services/otp-auth.service'
import { PasswordAuthService } from './services/password-auth.service'
import envConfig from 'src/shared/config'
import { I18nService, I18nContext } from 'nestjs-i18n'
import { Prisma } from '@prisma/client'

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

  async verifyTwoFactor(body: TwoFactorVerifyBodyType & { userAgent: string; ip: string }, res?: Response) {
    return this.twoFactorAuthService.verifyTwoFactor(body, res)
  }
}
