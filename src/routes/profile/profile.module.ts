import { Module, forwardRef } from '@nestjs/common'
import { PermissionModule } from '../permission/permission.module' // Import PermissionModule
import { RoleModule } from '../role/role.module' // Import RoleModule
import { UserModule } from '../user/user.module'
import { SharedModule } from 'src/shared/shared.module'
import { PermissionGuard } from 'src/shared/guards/permission.guard'
import { ProfileController } from './profile.controller'
import { ProfileRepository } from './profile.repository'
import { ProfileService } from './profile.service'

@Module({
  imports: [SharedModule, forwardRef(() => UserModule), RoleModule, PermissionModule],
  controllers: [ProfileController],
  providers: [ProfileService, ProfileRepository, PermissionGuard],
  exports: [ProfileService, ProfileRepository]
})
export class ProfileModule {}
