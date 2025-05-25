import { Injectable } from '@nestjs/common'
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
import { Response } from 'express'
import { Request } from 'express'
import { PrismaService } from 'src/shared/services/prisma.service'
import { AuditLogService } from 'src/routes/audit-log/audit-log.service'
import { OtpService } from 'src/routes/auth/providers/otp.service'
import { DeviceService } from 'src/routes/auth/providers/device.service'
import { AuthenticationService } from './services/authentication.service'
import { TwoFactorAuthService } from './services/two-factor-auth.service'
import { OtpAuthService } from './services/otp-auth.service'
import { DeviceAuthService } from './services/device-auth.service'
import { PasswordAuthService } from './services/password-auth.service'
import envConfig from 'src/shared/config'

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
    private readonly deviceAuthService: DeviceAuthService,
    private readonly passwordAuthService: PasswordAuthService
  ) {}

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
    const clientRefreshTokenJti = this.tokenService.extractRefreshTokenFromRequest(req)
    if (!clientRefreshTokenJti) {
      throw InvalidRefreshTokenException
    }
    const result = await this.tokenService.refreshTokenSilently(clientRefreshTokenJti, userAgent, ip)
    if (!result || !result.accessToken) {
      throw InvalidRefreshTokenException
    }
    if (res && result.refreshToken) {
      this.tokenService.setTokenCookies(
        res,
        result.accessToken,
        result.refreshToken,
        result.maxAgeForRefreshTokenCookie
      )
    } else if (res) {
      const accessTokenConfig = envConfig.cookie.accessToken
      res.cookie(accessTokenConfig.name, result.accessToken, {
        path: accessTokenConfig.path,
        domain: accessTokenConfig.domain,
        maxAge: accessTokenConfig.maxAge,
        httpOnly: accessTokenConfig.httpOnly,
        secure: accessTokenConfig.secure,
        sameSite: accessTokenConfig.sameSite
      })
    }
    return { accessToken: result.accessToken }
  }

  async generateTokens(payload: AccessTokenPayloadCreate, _prismaTx?: any, rememberMe?: boolean) {
    return this.tokenService.generateTokens(payload, undefined, rememberMe)
  }

  async logoutFromAllDevices(
    activeUser: AccessTokenPayload,
    ip: string,
    userAgent: string,
    req: Request,
    res: Response
  ) {
    await this.deviceAuthService.logoutFromAllDevices(activeUser, ip, userAgent)
    return this.authenticationService.logout(req, res)
  }

  async trustDevice(activeUser: AccessTokenPayload, ip: string, userAgent: string) {
    return this.deviceAuthService.trustDevice(activeUser, ip, userAgent)
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
