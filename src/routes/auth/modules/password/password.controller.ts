import { Controller, Post, Body, Res, Ip, Req, HttpCode, HttpStatus, UseGuards } from '@nestjs/common'
import { Response, Request } from 'express'
import { PasswordService } from './password.service'
import { InitiatePasswordResetDto, SetNewPasswordDto } from './password.dto'
import { IsPublic } from '../../shared/decorators/auth.decorator'
import { UserAgent } from 'src/shared/decorators/user-agent.decorator'
import { CookieNames } from '../../shared/constants/auth.constants'
import { AuthError } from '../../auth.error'
import { Throttle, ThrottlerGuard } from '@nestjs/throttler'

@UseGuards(ThrottlerGuard)
@Controller('auth/password')
export class PasswordController {
  constructor(private readonly passwordService: PasswordService) {}

  @IsPublic()
  @Post('initiate-reset')
  @HttpCode(HttpStatus.OK)
  @Throttle({ default: { limit: 5, ttl: 60000 } })
  async initiatePasswordReset(
    @Body() body: InitiatePasswordResetDto,
    @Ip() ip: string,
    @UserAgent() userAgent: string,
    @Res({ passthrough: true }) res: Response
  ) {
    return this.passwordService.initiatePasswordReset(body.email, ip, userAgent, res)
  }

  @IsPublic()
  @Post('set-new')
  @HttpCode(HttpStatus.OK)
  @Throttle({ default: { limit: 5, ttl: 60000 } })
  async setNewPassword(
    @Body() body: SetNewPasswordDto,
    @Ip() ip: string,
    @UserAgent() userAgent: string,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response
  ) {
    const sltCookieValue = req.cookies[CookieNames.SLT_TOKEN]
    if (!sltCookieValue) {
      throw AuthError.SLTCookieMissing()
    }
    return this.passwordService.setNewPassword(sltCookieValue, body, ip, userAgent, res)
  }
}
