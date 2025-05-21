import { Module } from '@nestjs/common'
import { AuditLogController } from './audit-log.controller'
import { AuditLogService } from './audit-log.service'
import { AuditLogRepository } from './audit-log.repo'

@Module({
  controllers: [AuditLogController],
  providers: [AuditLogService, AuditLogRepository],
  exports: [AuditLogService, AuditLogRepository]
})
export class AuditLogModule {}
