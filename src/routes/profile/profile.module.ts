import { Module, forwardRef } from '@nestjs/common'
import { PermissionModule } from '../permission/permission.module' // Import PermissionModule
import { RoleModule } from '../role/role.module' // Import RoleModule
import { UserModule } from '../user/user.module'
import { ProfileController } from './profile.controller'
import { ProfileRepository } from './profile.repository'
import { ProfileService } from './profile.service'

@Module({
  imports: [forwardRef(() => UserModule), RoleModule, PermissionModule],
  controllers: [ProfileController],
  providers: [ProfileService, ProfileRepository],
  exports: [ProfileService, ProfileRepository]
})
export class ProfileModule {}
