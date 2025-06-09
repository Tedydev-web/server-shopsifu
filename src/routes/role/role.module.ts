import { Module } from '@nestjs/common'
import { RoleController } from './role.controller'
import { RoleService } from './role.service'
import { RoleRepository } from './role.repository'
import { PermissionModule } from '../permission/permission.module'

@Module({
  imports: [PermissionModule], // Import PermissionModule
  controllers: [RoleController],
  providers: [RoleService, RoleRepository],
  exports: [RoleService, RoleRepository] // Export if other modules need to inject them
})
export class RoleModule {}
