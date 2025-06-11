import { Controller, Post, Body, Res, Ip, Req, HttpCode, HttpStatus, UseGuards } from '@nestjs/common'
import { Response, Request } from 'express'
import { PasswordService } from '../services/password.service'
import { InitiatePasswordResetDto, SetNewPasswordDto, ChangePasswordDto } from '../dtos/password.dto'
import { IsPublic, Auth } from '../../../shared/decorators/auth.decorator'
import { UserAgent } from 'src/shared/decorators/user-agent.decorator'
import { CookieNames } from '../auth.constants'
import { AuthError } from '../auth.error'
import { Throttle, ThrottlerGuard } from '@nestjs/throttler'
import { ActiveUser } from 'src/shared/decorators/active-user.decorator'
import { ActiveUserData } from 'src/shared/types/active-user.type'
import { PoliciesGuard } from 'src/shared/guards/policies.guard'
import { CheckPolicies } from 'src/shared/decorators/check-policies.decorator'
import { Action, AppAbility } from 'src/shared/providers/casl/casl-ability.factory'

@UseGuards(ThrottlerGuard)
@Auth()
@Controller('auth/password')
export class PasswordController {
  constructor(private readonly passwordService: PasswordService) {}

  @Post('change')
  @UseGuards(PoliciesGuard)
  @CheckPolicies((ability: AppAbility) => ability.can(Action.Update, 'UserProfile'))
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
