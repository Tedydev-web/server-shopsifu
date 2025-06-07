import { Controller, Get, Logger, Post, Body, HttpCode, HttpStatus, Ip, UseGuards } from '@nestjs/common'
import { Auth } from '../auth/shared/decorators/auth.decorator'
import { ActiveUser } from '../auth/shared/decorators/active-user.decorator'
import { AccessTokenPayload } from '../auth/shared/auth.types'
import { ProfileService } from './profile.service'
import { ProfileResponseDto, ChangePasswordDto } from './profile.dto'
import { SuccessMessage } from 'src/shared/decorators/success-message.decorator'
import { UserAgent } from 'src/shared/decorators/user-agent.decorator'
import { Throttle, ThrottlerGuard } from '@nestjs/throttler'

@Auth()
@UseGuards(ThrottlerGuard)
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
  @Throttle({ default: { limit: 5, ttl: 60000 } })
  async changePassword(
    @ActiveUser() activeUser: AccessTokenPayload,
    @Body() body: ChangePasswordDto,
    @Ip() ip: string,
    @UserAgent() userAgent: string
  ): Promise<void> {
    this.logger.debug(`[POST /profile/change-password] Called by user ${activeUser.userId}`)
    await this.profileService.changePassword(activeUser, body, ip, userAgent)
  }
}
