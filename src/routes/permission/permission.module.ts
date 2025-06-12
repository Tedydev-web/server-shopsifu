import { Module, forwardRef } from '@nestjs/common'
import { UserModule } from 'src/routes/user/user.module'
import { SharedModule } from 'src/shared/shared.module'
import { PermissionController } from './permission.controller'
import { PermissionRepository } from './permission.repository'
import { PermissionService } from './permission.service'

@Module({
  imports: [SharedModule, forwardRef(() => UserModule)],
  controllers: [PermissionController],
  providers: [PermissionService, PermissionRepository],
  exports: [PermissionService, PermissionRepository]
})
export class PermissionModule {}
