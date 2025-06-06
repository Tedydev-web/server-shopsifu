import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Ip,
  Logger,
  Post,
  Req,
  Res,
  HttpException,
  Inject,
  forwardRef
} from '@nestjs/common'
import { Request, Response } from 'express'
import { ZodSerializerDto } from 'nestjs-zod'
import { I18nService, I18nContext } from 'nestjs-i18n'
import { Throttle } from '@nestjs/throttler'

import { CoreService } from './core.service'
import { TypeOfVerificationCode, CookieNames } from 'src/routes/auth/shared/constants/auth.constants'
import {
  CompleteRegistrationDto,
  InitiateRegistrationDto,
  LoginDto,
  RefreshTokenDto,
  RefreshTokenResponseDto
} from './auth.dto'
import { MessageResDTO } from 'src/shared/dtos/response.dto'
import { OtpService } from 'src/routes/auth/modules/otp/otp.service'
import { UserAgent } from 'src/shared/decorators/user-agent.decorator'
import { AuthError } from 'src/routes/auth/auth.error'
import { ActiveUser } from 'src/routes/auth/shared/decorators/active-user.decorator'
import { AccessTokenPayload, ICookieService, ITokenService } from 'src/routes/auth/shared/auth.types'
import { IsPublic } from 'src/routes/auth/shared/decorators/auth.decorator'
import { COOKIE_SERVICE, SLT_SERVICE, TOKEN_SERVICE } from 'src/shared/constants/injection.tokens'
import { I18nTranslations, I18nPath } from 'src/generated/i18n.generated'
import { AuthVerificationService } from 'src/routes/auth/services/auth-verification.service'
import { SLTService } from 'src/routes/auth/shared/services/slt.service'

@Controller('auth')
export class CoreController {
  private readonly logger = new Logger(CoreController.name)

  constructor(
    private readonly coreService: CoreService,
    private readonly otpService: OtpService,
    @Inject(forwardRef(() => AuthVerificationService))
    private readonly authVerificationService: AuthVerificationService,
    @Inject(COOKIE_SERVICE) private readonly cookieService: ICookieService,
    @Inject(TOKEN_SERVICE) private readonly tokenService: ITokenService,
    private readonly i18nService: I18nService<I18nTranslations>,
    @Inject(SLT_SERVICE) private readonly sltService: SLTService
  ) {}

  @Throttle({ default: { limit: 5, ttl: 60000 } })
  @IsPublic()
  @Post('initiate-registration')
  @HttpCode(HttpStatus.OK)
  @ZodSerializerDto(MessageResDTO)
  async initiateRegistration(
    @Body() body: InitiateRegistrationDto,
    @Ip() ip: string,
    @UserAgent() userAgent: string,
    @Res({ passthrough: true }) res: Response
  ): Promise<MessageResDTO> {
    this.logger.log(`[Registration] Attempt from IP: ${ip}, User-Agent: ${userAgent}`)

    const verificationResult = await this.coreService.initiateRegistration(body.email, ip, userAgent, res)

    return {
      message: verificationResult.message || this.i18nService.t('auth.Auth.Register.EmailSent' as I18nPath)
    }
  }

  /**
   * Hoàn thành đăng ký
   */
  @Throttle({ default: { limit: 5, ttl: 60000 } })
  @IsPublic()
  @Post('complete-registration')
  async completeRegistration(
    @Body() body: CompleteRegistrationDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response
  ): Promise<MessageResDTO> {
    this.logger.log(`[completeRegistration] Attempting to complete registration for email associated with SLT.`)

    const sltCookie = req.cookies[CookieNames.SLT_TOKEN]
    if (!sltCookie) {
      throw AuthError.SLTCookieMissing()
    }

    if (body.password !== body.confirmPassword) {
      throw AuthError.InvalidPassword()
    }

    const result = await this.coreService.completeRegistrationWithSlt(
      sltCookie,
      body,
      req.ip,
      req.headers['user-agent']
    )

    // Xóa cookie sau khi hoàn tất
    this.cookieService.clearSltCookie(res)

    return { message: result.message }
  }

  @Throttle({ default: { limit: 5, ttl: 60000 } })
  @IsPublic()
  @Post('login')
  @HttpCode(HttpStatus.OK)
  async login(
    @Body() body: LoginDto,
    @Ip() ip: string,
    @UserAgent() userAgent: string,
    @Res({ passthrough: true }) res: Response
  ) {
    this.logger.log(`[Login] Attempt for user ${body.emailOrUsername} from IP: ${ip}, User-Agent: ${userAgent}`)
    return this.coreService.initiateLogin(body, ip, userAgent, res)
  }

  /**
   * Làm mới token
   */
  @Throttle({ default: { limit: 10, ttl: 60000 } })
  @IsPublic()
  @Post('refresh-token')
  async refreshToken(
    @Body() _: RefreshTokenDto,
    @UserAgent() userAgent: string,
    @Ip() ip: string,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response
  ): Promise<RefreshTokenResponseDto> {
    try {
      const refreshToken = this.tokenService.extractRefreshTokenFromRequest(req)

      if (!refreshToken) {
        throw AuthError.MissingRefreshToken()
      }

      const deviceInfo = {
        ipAddress: ip,
        userAgent
      }

      const { accessToken } = await this.coreService.refreshToken(refreshToken, deviceInfo, res)

      return { accessToken }
    } catch (error) {
      if (error instanceof AuthError) throw error
      throw AuthError.InternalServerError(error.message)
    }
  }

  @Post('logout')
  @HttpCode(HttpStatus.OK)
  @ZodSerializerDto(MessageResDTO)
  async logout(
    @ActiveUser() activeUser: AccessTokenPayload,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response
  ): Promise<MessageResDTO> {
    await this.coreService.logout(activeUser.userId, activeUser.sessionId, req, res)
    return {
      message: this.i18nService.t('auth.Auth.Logout.Success')
    }
  }
}
