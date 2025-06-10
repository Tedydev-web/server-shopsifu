import { Controller, Get, Logger, Post, Body, HttpCode, HttpStatus, Ip, Res, UseGuards, Patch } from '@nestjs/common'
import { Auth } from '../../shared/decorators/auth.decorator'
import { ActiveUser } from '../../shared/decorators/active-user.decorator'
import { ProfileService } from './profile.service'
import { UpdateProfileDto } from './profile.dto'
import { PoliciesGuard } from 'src/shared/guards/policies.guard'
import { CheckPolicies } from 'src/shared/decorators/check-policies.decorator'
import { Action, AppAbility } from 'src/shared/casl/casl-ability.factory'
import { ProfileRepository } from './profile.repository'
import { UserWithProfileAndRole } from 'src/routes/user/user.repository'
import { UpdateProfilePolicyHandler } from './profile.policies'
import { I18nService } from 'nestjs-i18n'

@Auth()
@Controller('profile')
export class ProfileController {
  private readonly logger = new Logger(ProfileController.name)
  constructor(
    private readonly profileService: ProfileService,
    private readonly profileRepository: ProfileRepository,
    private readonly i18n: I18nService
  ) {}

  @Get()
  @UseGuards(PoliciesGuard)
  @CheckPolicies((ability: AppAbility) => ability.can(Action.Read, 'UserProfile'))
  @HttpCode(HttpStatus.OK)
  async getProfile(@ActiveUser() activeUser: UserWithProfileAndRole) {
    this.logger.debug(`[GET /profile] Called by user ${activeUser.id}`)
    const profileData = await this.profileService.getProfile(activeUser.id)
    return {
      message: 'profile.success.get',
      data: profileData
    }
  }

  @Patch()
  @UseGuards(PoliciesGuard)
  @CheckPolicies(UpdateProfilePolicyHandler)
  @HttpCode(HttpStatus.OK)
  async updateProfile(@ActiveUser() activeUser: UserWithProfileAndRole, @Body() body: UpdateProfileDto) {
    this.logger.debug(`[PATCH /profile] Called by user ${activeUser.id}`)
    const updatedProfile = await this.profileService.updateProfile(activeUser.id, body)
    return {
      message: 'profile.success.update',
      data: updatedProfile
    }
  }
}
