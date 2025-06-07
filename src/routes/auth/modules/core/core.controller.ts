import { Body, Controller, HttpCode, HttpStatus, Ip, Logger, Post, Req, Res, Inject, forwardRef } from '@nestjs/common'
import { Request, Response } from 'express'
import { I18nService } from 'nestjs-i18n'
import { Throttle } from '@nestjs/throttler'

import { CoreService } from './core.service'
import { CookieNames } from 'src/routes/auth/shared/constants/auth.constants'
import {
  CompleteRegistrationDto,
  InitiateRegistrationDto,
  LoginDto,
  RefreshTokenDto,
  RefreshTokenResponseDto
} from './core.dto'
import { MessageResDTO } from 'src/shared/dtos/response.dto'
import { UserAgent } from 'src/shared/decorators/user-agent.decorator'
import { AuthError } from 'src/routes/auth/auth.error'
import { ActiveUser } from 'src/routes/auth/shared/decorators/active-user.decorator'
import { AccessTokenPayload, ICookieService, ITokenService } from 'src/routes/auth/shared/auth.types'
import { IsPublic } from 'src/routes/auth/shared/decorators/auth.decorator'
import { COOKIE_SERVICE, TOKEN_SERVICE } from 'src/shared/constants/injection.tokens'
import { AuthVerificationService } from 'src/shared/services/auth-verification.service'

@Controller('auth')
export class CoreController {
  private readonly logger = new Logger(CoreController.name)

  constructor(
    private readonly coreService: CoreService,
    @Inject(forwardRef(() => AuthVerificationService))
    private readonly authVerificationService: AuthVerificationService,
    @Inject(COOKIE_SERVICE) private readonly cookieService: ICookieService,
    @Inject(TOKEN_SERVICE) private readonly tokenService: ITokenService,
    private readonly i18nService: I18nService
  ) {}

  @Throttle({ default: { limit: 5, ttl: 60000 } })
  @IsPublic()
  @Post('initiate-registration')
  @HttpCode(HttpStatus.OK)
  async initiateRegistration(
    @Body() body: InitiateRegistrationDto,
    @Ip() ip: string,
    @UserAgent() userAgent: string,
    @Res({ passthrough: true }) res: Response
  ): Promise<any> {
    this.logger.log(`[Registration] Attempt from IP: ${ip}, User-Agent: ${userAgent}`)
    return this.coreService.initiateRegistration(body.email, ip, userAgent, res)
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
  ): Promise<{ message: string }> {
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

    return result
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
    @UserAgent() userAgent: string,
    @Ip() ip: string,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response
  ): Promise<any> {
    const refreshToken = this.tokenService.extractRefreshTokenFromRequest(req)

    if (!refreshToken) {
      throw AuthError.MissingRefreshToken()
    }

    const deviceInfo = {
      ipAddress: ip,
      userAgent
    }

    return this.coreService.refreshToken(refreshToken, deviceInfo, res)
  }

  @Post('logout')
  @HttpCode(HttpStatus.OK)
  async logout(
    @ActiveUser() activeUser: AccessTokenPayload,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response
  ): Promise<{ message: string }> {
    return this.coreService.logout(activeUser.userId, activeUser.sessionId, req, res)
  }
}
