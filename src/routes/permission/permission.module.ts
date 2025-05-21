import { Module } from '@nestjs/common'
import { PermissionService } from './permission.service'
import { PermissionController } from './permission.controller'
import { PermissionRepo } from './permission.repo'
import { AuditLogModule } from 'src/routes/audit-log/audit-log.module'

@Module({
  imports: [AuditLogModule],
  providers: [PermissionService, PermissionRepo],
  controllers: [PermissionController],
  exports: [PermissionService, PermissionRepo]
})
export class PermissionModule {}
