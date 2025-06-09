import { Controller, Get, Logger, Post, Body, HttpCode, HttpStatus, Ip, Res } from '@nestjs/common'
import { Auth } from '../../shared/decorators/auth.decorator'
import { ActiveUser } from '../../shared/decorators/active-user.decorator'
import { AccessTokenPayload } from '../../shared/types/auth.types'
import { ProfileService } from './profile.service'
import { ProfileResponseDto, ChangePasswordDto } from './profile.dto'
import { SuccessMessage } from 'src/shared/decorators/success-message.decorator'
import { UserAgent } from 'src/shared/decorators/user-agent.decorator'
import { Response } from 'express'

@Auth()
@Controller('profile')
export class ProfileController {
  private readonly logger = new Logger(ProfileController.name)
  constructor(private readonly profileService: ProfileService) {}

  @Get()
  @HttpCode(HttpStatus.OK)
  getProfile(@ActiveUser() activeUser: AccessTokenPayload): Promise<ProfileResponseDto> {
    this.logger.debug(`[GET /profile] Called by user ${activeUser.userId}`)
    return this.profileService.getProfile(activeUser.userId)
  }

  @Post('change-password')
  @HttpCode(HttpStatus.OK)
  @SuccessMessage('auth.Auth.Password.ChangeSuccess')
  async changePassword(
    @ActiveUser() activeUser: AccessTokenPayload,
    @Body() body: ChangePasswordDto,
    @Ip() ip: string,
    @UserAgent() userAgent: string,
    @Res({ passthrough: true }) res: Response
  ): Promise<any> {
    this.logger.debug(`[POST /profile/password] Called by user ${activeUser.userId}`)
    return this.profileService.changePassword(activeUser, body, ip, userAgent, res)
  }
}
