import { Module } from '@nestjs/common'
import { PermissionService } from './permission.service'
import { PermissionRepository } from './permission.repository'
import { PermissionController } from './permission.controller'
import {
  CanCreatePermissionPolicy,
  CanDeletePermissionPolicy,
  CanReadPermissionPolicy,
  CanUpdatePermissionPolicy
} from './permission.policies'

@Module({
  controllers: [PermissionController],
  providers: [
    PermissionService,
    PermissionRepository,
    ...CanCreatePermissionPolicy,
    ...CanDeletePermissionPolicy,
    ...CanReadPermissionPolicy,
    ...CanUpdatePermissionPolicy
  ],
  exports: [PermissionService, PermissionRepository]
})
export class PermissionModule {}
