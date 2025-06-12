import { Controller, Get, Logger, Body, HttpCode, HttpStatus, UseGuards, Patch } from '@nestjs/common'
import { Auth } from '../../shared/decorators/auth.decorator'
import { ActiveUser } from '../../shared/decorators/active-user.decorator'
import { ProfileService } from './profile.service'
import { UpdateProfileDto, ProfileResponseDto } from './profile.dto'
import { PermissionGuard } from 'src/shared/guards/permission.guard'
import { PermissionCondition, RequirePermissions } from 'src/shared/decorators/permissions.decorator'
import { ActiveUserData } from 'src/shared/types/active-user.type'

@Auth()
@UseGuards(PermissionGuard)
@Controller('profile')
export class ProfileController {
  private readonly logger = new Logger(ProfileController.name)
  constructor(private readonly profileService: ProfileService) {}

  @Get()
  @RequirePermissions(['Profile:read:own'])
  @HttpCode(HttpStatus.OK)
  async getProfile(@ActiveUser() activeUser: ActiveUserData): Promise<ProfileResponseDto> {
    this.logger.debug(`[GET /profile] Called by user ${activeUser.id}`)
    const profile = await this.profileService.getProfile(activeUser.id)
    return profile
  }

  @Patch()
  @RequirePermissions(['Profile:update:own'])
  @HttpCode(HttpStatus.OK)
  async updateProfile(
    @ActiveUser() activeUser: ActiveUserData,
    @Body() body: UpdateProfileDto
  ): Promise<ProfileResponseDto> {
    this.logger.debug(`[PATCH /profile] Called by user ${activeUser.id}`)
    return this.profileService.updateProfile(activeUser.id, body)
  }
}
