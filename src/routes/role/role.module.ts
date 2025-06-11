import { Module } from '@nestjs/common'
import { RoleController } from './role.controller'
import { RoleService } from './role.service'
import { RoleRepository } from './role.repository'
import { PermissionModule } from '../permission/permission.module'
import { CanCreateRolePolicy, CanDeleteRolePolicy, CanReadRolePolicy, CanUpdateRolePolicy } from './role.policies'

@Module({
  imports: [PermissionModule], // Import PermissionModule
  controllers: [RoleController],
  providers: [
    RoleService,
    RoleRepository,
    ...CanCreateRolePolicy,
    ...CanDeleteRolePolicy,
    ...CanReadRolePolicy,
    ...CanUpdateRolePolicy
  ],
  exports: [RoleService, RoleRepository] // Export if other modules need to inject them
})
export class RoleModule {}
