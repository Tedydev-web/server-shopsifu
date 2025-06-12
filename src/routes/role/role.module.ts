import { Module, forwardRef } from '@nestjs/common'
import { PermissionModule } from 'src/routes/permission/permission.module'
import { UserModule } from 'src/routes/user/user.module'
import { SharedModule } from 'src/shared/shared.module'
import { RoleController } from './role.controller'
import { RoleRepository } from './role.repository'
import { RoleService } from './role.service'

@Module({
  imports: [SharedModule, forwardRef(() => UserModule), forwardRef(() => PermissionModule)],
  controllers: [RoleController],
  providers: [RoleService, RoleRepository],
  exports: [RoleService, RoleRepository]
})
export class RoleModule {}
