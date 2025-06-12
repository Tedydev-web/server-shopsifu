import { Controller, Post, Body, Res, Req, HttpCode, HttpStatus, UseGuards, Ip } from '@nestjs/common'
import { Request, Response } from 'express'
import { PasswordService } from '../services/password.service'
import { ChangePasswordDto, InitiatePasswordResetDto, SetNewPasswordDto } from '../dtos/password.dto'
import { IsPublic, Auth } from 'src/shared/decorators/auth.decorator'
import { ThrottlerGuard } from '@nestjs/throttler'
import { ActiveUser } from 'src/shared/decorators/active-user.decorator'
import { UserAgent } from 'src/shared/decorators/user-agent.decorator'
import { ActiveUserData } from 'src/shared/types/active-user.type'
import { CookieNames } from '../auth.constants'
import { AuthError } from '../auth.error'
import { Throttle } from '@nestjs/throttler'

@Auth()
@UseGuards(ThrottlerGuard)
@Controller('auth/password')
export class PasswordController {
  constructor(private readonly passwordService: PasswordService) {}

  @Post('change')
  async changePassword(
    @ActiveUser() activeUser: ActiveUserData,
    @Body() body: ChangePasswordDto,
    @Ip() ip: string,
    @UserAgent() userAgent: string,
    @Res({ passthrough: true }) res: Response
  ) {
    return this.passwordService.changePassword(activeUser, body, ip, userAgent, res)
  }

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
