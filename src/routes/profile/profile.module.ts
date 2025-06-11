import { Module, forwardRef } from '@nestjs/common'
import { ProfileController } from './profile.controller'
import { ProfileService } from './profile.service'
import { ProfileRepository } from './profile.repository'
import { RoleModule } from '../role/role.module' // Import RoleModule
import { PermissionModule } from '../permission/permission.module' // Import PermissionModule
import { UserModule } from '../user/user.module'

@Module({
  imports: [forwardRef(() => UserModule), RoleModule, PermissionModule],
  controllers: [ProfileController],
  providers: [ProfileService, ProfileRepository],
  exports: [ProfileService, ProfileRepository]
})
export class ProfileModule {}
