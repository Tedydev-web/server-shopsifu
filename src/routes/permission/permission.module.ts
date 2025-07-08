import { Module } from '@nestjs/common'
import { PermissionController } from 'src/routes/permission/permission.controller'
import { PermissionRepo } from 'src/routes/permission/permission.repo'
import { PermissionService } from 'src/routes/permission/permission.service'

@Module({
  providers: [PermissionService, PermissionRepo],
  controllers: [PermissionController],
})
export class PermissionModule {}
