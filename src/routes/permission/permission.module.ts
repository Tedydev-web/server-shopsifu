import { Module } from '@nestjs/common'
import { PermissionController } from 'src/routes/permission/permission.controller'
import { PermissionRepo } from 'src/routes/permission/permission.repo'
import { PermissionService } from 'src/routes/permission/permission.service'
import { PaginationService } from 'src/shared/services/pagination.service'

@Module({
  providers: [PermissionService, PermissionRepo, PaginationService],
  controllers: [PermissionController],
})
export class PermissionModule {}
