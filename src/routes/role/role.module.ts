import { Module, forwardRef } from '@nestjs/common'
import { RoleController } from './role.controller'
import { RoleService } from './role.service'
import { RoleRepository } from './role.repository'
import { PermissionModule } from '../permission/permission.module'
import { UserModule } from '../user/user.module'

@Module({
  imports: [
    PermissionModule,
    forwardRef(() => UserModule) // Import UserModule to resolve PermissionGuard dependencies
  ],
  controllers: [RoleController],
  providers: [RoleService, RoleRepository],
  exports: [RoleService, RoleRepository] // Export if other modules need to inject them
})
export class RoleModule {}
