import { Module, forwardRef } from '@nestjs/common'
import { ProfileController } from './profile.controller'
import { ProfileService } from './profile.service'
import { ProfileRepository } from './profile.repository'
import { RoleModule } from '../role/role.module' // Import RoleModule
import { PermissionModule } from '../permission/permission.module' // Import PermissionModule
import { UpdateProfilePolicyHandler } from './profile.policies'
import { UserModule } from '../user/user.module'

@Module({
  imports: [forwardRef(() => UserModule), RoleModule, PermissionModule],
  controllers: [ProfileController],
  providers: [ProfileService, ProfileRepository, UpdateProfilePolicyHandler],
  exports: [ProfileService, ProfileRepository]
})
export class ProfileModule {}
