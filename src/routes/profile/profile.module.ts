import { Module } from '@nestjs/common'
import { ProfileController } from './profile.controller'
import { ProfileService } from './profile.service'
import { ProfileRepository } from './profile.repository'
import { AuthModule } from '../auth/auth.module'
import { RoleModule } from '../role/role.module' // Import RoleModule
import { PermissionModule } from '../permission/permission.module' // Import PermissionModule

@Module({
  imports: [AuthModule, RoleModule, PermissionModule], // Add RoleModule and PermissionModule
  controllers: [ProfileController],
  providers: [ProfileService, ProfileRepository],
  exports: [ProfileService]
})
export class ProfileModule {}
