import { Body, Controller, HttpCode, HttpStatus, Ip, Logger, Post, Req, Res, Inject } from '@nestjs/common'
import { Request, Response } from 'express'
import { Throttle } from '@nestjs/throttler'

import { CoreService } from '../services/core.service'
import { CookieNames } from 'src/routes/auth/auth.constants'
import { CompleteRegistrationDto, InitiateRegistrationDto, LoginDto } from '../dtos/core.dto'
import { UserAgent } from 'src/shared/decorators/user-agent.decorator'
import { AuthError } from 'src/routes/auth/auth.error'
import { ActiveUser } from 'src/shared/decorators/active-user.decorator'
import { Auth } from 'src/shared/decorators/auth.decorator'
import { AccessTokenPayload, ICookieService } from 'src/routes/auth/auth.types'
import { IsPublic } from 'src/shared/decorators/auth.decorator'
import { COOKIE_SERVICE } from 'src/shared/constants/injection.tokens'

@Controller('auth')
export class CoreController {
  private readonly logger = new Logger(CoreController.name)

  constructor(
    private readonly coreService: CoreService,
    @Inject(COOKIE_SERVICE) private readonly cookieService: ICookieService
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
    this.logger.debug(
      `[CoreController] initiateRegistration called with email: "${body.email}" (type: ${typeof body.email})`
    )
    return this.coreService.initiateRegistration(body.email, ip, userAgent, res)
  }

  /**
   * Hoàn thành đăng ký
   */
  @Throttle({ default: { limit: 5, ttl: 60000 } })
  @IsPublic()
  @Post('complete-registration')
  @HttpCode(HttpStatus.CREATED)
  async completeRegistration(
    @Body() body: CompleteRegistrationDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response
  ): Promise<any> {
    this.logger.log(`[completeRegistration] Attempting to complete registration for email associated with SLT.`)

    const sltCookie = req.cookies[CookieNames.SLT_TOKEN]
    if (!sltCookie) {
      throw AuthError.SLTCookieMissing()
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
  @HttpCode(HttpStatus.OK)
  async refreshToken(
    @UserAgent() userAgent: string,
    @Ip() ip: string,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response
  ): Promise<any> {
    const deviceInfo = {
      ipAddress: ip,
      userAgent
    }
    return this.coreService.refreshToken(req, deviceInfo, res)
  }

  @Auth()
  @Post('logout')
  @HttpCode(HttpStatus.OK)
  async logout(
    @ActiveUser() activeUser: AccessTokenPayload,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response
  ): Promise<any> {
    return this.coreService.logout(activeUser.userId, activeUser.sessionId, req, res)
  }
}
