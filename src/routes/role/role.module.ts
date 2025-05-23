import { Module } from '@nestjs/common'
import { RoleService } from './role.service'
import { RoleController } from './role.controller'
import { RoleRepo } from './role.repo'
import { AuditLogModule } from 'src/routes/audit-log/audit-log.module'
import { PermissionModule } from 'src/routes/permission/permission.module'

@Module({
  imports: [AuditLogModule, PermissionModule],
  providers: [RoleService, RoleRepo],
  controllers: [RoleController],
  exports: [RoleService, RoleRepo]
})
export class RoleModule {}
