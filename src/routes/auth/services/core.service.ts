import { Injectable } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { addMilliseconds } from 'date-fns'
import { DisableTwoFactorBodyDTO, LoginBodyDTO, RegisterBodyDTO, SendOTPBodyDTO } from '../dtos/auth.dto'
import { VerificationCodeRepository } from '../repositories/verification-code.repository'
import { isUniqueConstraintPrismaError } from 'src/shared/helpers'
import { SharedUserRepository } from 'src/shared/repositories/shared-user.repo'
import { HashingService } from 'src/shared/services/hashing.service'
import { TokenService } from 'src/shared/services/token.service'
import { TypeOfVerificationCode } from 'src/shared/constants/auth.constant'
import { EmailService } from 'src/shared/services/email.service'
import { AccessTokenPayloadCreate } from 'src/shared/types/jwt.type'
import { AuthError } from '../auth.error'
import { TwoFactorService } from 'src/shared/services/2fa.service'
import { CookieService } from 'src/shared/services/cookie.service'
import { Response, Request } from 'express'
import { SessionService } from 'src/shared/services/session.service'
import { DeviceService } from 'src/routes/device/device.service'
import { CryptoService } from 'src/shared/services/crypto.service'
import { EnvConfigType } from 'src/shared/config'
import { SessionRepository } from '../repositories/session.repository'
import { OtpService } from './otp.service'
import { AuthRepository } from '../repositories/auth.repo'
import { SharedRoleRepository } from 'src/shared/repositories/shared-role.repo'
import { I18nService } from 'nestjs-i18n'
import { I18nTranslations } from 'src/generated/i18n.generated'

@Injectable()
export class CoreAuthService {
  constructor(
    private readonly hashingService: HashingService,
    private readonly sharedRoleRepository: SharedRoleRepository,
    private readonly verificationCodeRepository: VerificationCodeRepository,
    private readonly sharedUserRepository: SharedUserRepository,
    private readonly emailService: EmailService,
    private readonly tokenService: TokenService,
    private readonly twoFactorService: TwoFactorService,
    private readonly cookieService: CookieService,
    private readonly configService: ConfigService<EnvConfigType>,
    private readonly cryptoService: CryptoService,
    private readonly deviceService: DeviceService,
    private readonly sessionService: SessionService,
    private readonly sessionRepository: SessionRepository,
    private readonly otpService: OtpService,
    private readonly authRepository: AuthRepository,
    private readonly i18n: I18nService<I18nTranslations>,
  ) {}

  async register(body: RegisterBodyDTO, req: Request) {
    try {
      await this.otpService.validateVerificationCode({
        email: body.email,
        code: body.code,
        type: TypeOfVerificationCode.REGISTER,
        req,
      })
      const clientRoleId = await this.sharedRoleRepository.getClientRoleId()
      const hashedPassword = await this.hashingService.hash(body.password)

      await this.authRepository.createUser({
        ...body,
        password: hashedPassword,
        roleId: clientRoleId,
      })

      await this.verificationCodeRepository.delete({
        email: body.email,
        code: body.code,
        type: TypeOfVerificationCode.REGISTER,
      })

      return {
        message: this.i18n.t('auth.success.REGISTER_SUCCESS'),
      }
    } catch (error) {
      if (isUniqueConstraintPrismaError(error)) {
        throw AuthError.EmailAlreadyExists
      }
      throw error
    }
  }

  async sendOTP(body: SendOTPBodyDTO) {
    const user = await this.sharedUserRepository.findUnique({ email: body.email })
    if (body.type === TypeOfVerificationCode.REGISTER && user) {
      throw AuthError.EmailAlreadyExists
    }
    if (body.type === TypeOfVerificationCode.FORGOT_PASSWORD && !user) {
      throw AuthError.EmailNotFound
    }
    const code = this.cryptoService.generateOTP()
    await this.verificationCodeRepository.create({
      email: body.email,
      code,
      type: body.type,
      expiresAt: addMilliseconds(new Date(), this.configService.get('timeouts').otp),
    })
    await this.emailService.sendOTP({
      email: body.email,
      code,
    })
    return {
      message: this.i18n.t('auth.success.SEND_OTP_SUCCESS'),
    }
  }

  async login(body: LoginBodyDTO, req: Request, res: Response) {
    const user = await this.authRepository.findUniqueUserIncludeRole({ email: body.email })
    if (!user) {
      throw AuthError.InvalidCredentials
    }

    const isPasswordMatch = await this.hashingService.compare(body.password, user.password)
    if (!isPasswordMatch) {
      throw AuthError.InvalidCredentials
    }

    const device = await this.deviceService.findOrCreateDevice(user.id, req)

    const refreshTokenExpiresInMs = this.configService.get('timeouts').refreshToken
    const refreshTokenExpiresAt = addMilliseconds(new Date(), refreshTokenExpiresInMs)

    const session = await this.sessionRepository.createSession({
      userId: user.id,
      deviceId: device.id,
      ipAddress: device.ip,
      userAgent: device.userAgent,
      expiresAt: refreshTokenExpiresAt,
    })

    await this.sessionService.createSession(session)

    const userRole = await this.sharedRoleRepository.getRoleById(user.roleId)
    if (!userRole) {
      throw AuthError.RoleNotFound
    }
    const { accessToken, refreshToken } = await this.generateTokens({
      userId: user.id,
      sessionId: session.id,
      roleId: user.roleId,
      roleName: userRole.name,
    })

    this.cookieService.setTokenCookies(res, accessToken, refreshToken)

    return {
      message: this.i18n.t('auth.success.LOGIN_SUCCESS'),
    }
  }

  async generateTokens({ userId, sessionId, roleId, roleName }: AccessTokenPayloadCreate) {
    const [accessToken, refreshToken] = await Promise.all([
      this.tokenService.signAccessToken({
        userId,
        sessionId,
        roleId,
        roleName,
      }),
      this.tokenService.signRefreshToken({
        userId,
        sessionId,
      }),
    ])
    return { accessToken, refreshToken }
  }

  async setupTwoFactorAuth(userId: number) {
    const user = await this.sharedUserRepository.findUnique({ id: userId })
    if (!user) {
      throw AuthError.UserNotFound
    }
    if (user.totpSecret) {
      throw AuthError.TOTPAlreadyEnabled
    }
    const { secret, uri } = this.twoFactorService.generateTOTPSecret(user.email)
    return { secret, uri }
  }

  async disableTwoFactorAuth(data: DisableTwoFactorBodyDTO & { userId: number }) {
    const user = await this.sharedUserRepository.findUnique({ id: data.userId })
    if (!user || !user.totpSecret) {
      throw AuthError.UserNotFound
    }
    if (!data.code) {
      throw AuthError.InvalidOTP
    }
    const isValid = this.twoFactorService.verifyTOTP({ token: data.code, secret: user.totpSecret })
    if (!isValid) {
      throw AuthError.InvalidOTP
    }
    await this.sharedUserRepository.update({ id: data.userId }, { totpSecret: null })
    return {
      message: this.i18n.t('auth.success.DISABLE_2FA_SUCCESS'),
    }
  }
}
