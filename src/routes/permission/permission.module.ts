import { Module, forwardRef } from '@nestjs/common'
import { PermissionService } from './permission.service'
import { PermissionController } from './permission.controller'
import { PermissionRepository } from './permission.repository'
import { SharedModule } from 'src/shared/shared.module'
import { UserModule } from 'src/routes/user/user.module'

@Module({
  imports: [SharedModule, forwardRef(() => UserModule)],
  controllers: [PermissionController],
  providers: [PermissionService, PermissionRepository],
  exports: [PermissionService, PermissionRepository]
})
export class PermissionModule {}
