import { Controller, Get, Logger, Body, HttpCode, HttpStatus, UseGuards, Patch } from '@nestjs/common'
import { Auth } from '../../shared/decorators/auth.decorator'
import { ActiveUser } from '../../shared/decorators/active-user.decorator'
import { ProfileService } from './profile.service'
import { UpdateProfileDto, ProfileResponseDto } from './profile.dto'
import { PoliciesGuard } from 'src/shared/guards/policies.guard'
import { CheckPolicies } from 'src/shared/decorators/check-policies.decorator'
import { ActiveUserData } from 'src/shared/types/active-user.type'
import { Action, AppAbility } from 'src/shared/providers/casl/casl-ability.factory'

@Auth()
@UseGuards(PoliciesGuard)
@Controller('profile')
export class ProfileController {
  private readonly logger = new Logger(ProfileController.name)
  constructor(private readonly profileService: ProfileService) {}

  @Get()
  @CheckPolicies((ability: AppAbility) => ability.can(Action.Read, 'UserProfile'))
  @HttpCode(HttpStatus.OK)
  async getProfile(@ActiveUser() activeUser: ActiveUserData): Promise<ProfileResponseDto> {
    this.logger.debug(`[GET /profile] Called by user ${activeUser.id}`)
    return this.profileService.getProfile(activeUser.id)
  }

  @Patch()
  @CheckPolicies((ability: AppAbility) => ability.can(Action.Update, 'UserProfile'))
  @HttpCode(HttpStatus.OK)
  async updateProfile(
    @ActiveUser() activeUser: ActiveUserData,
    @Body() body: UpdateProfileDto
  ): Promise<ProfileResponseDto> {
    this.logger.debug(`[PATCH /profile] Called by user ${activeUser.id}`)
    return this.profileService.updateProfile(activeUser.id, body)
  }
}
