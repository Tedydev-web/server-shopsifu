import { Module } from '@nestjs/common'
import { PermissionService } from './permission.service'
import { PermissionRepository } from './permission.repository'
import { PermissionController } from './permission.controller'

@Module({
  controllers: [PermissionController],
  providers: [PermissionService, PermissionRepository],
  exports: [PermissionService, PermissionRepository]
})
export class PermissionModule {}
