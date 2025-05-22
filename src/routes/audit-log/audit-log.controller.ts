import { Controller, Get, Query, Param, HttpStatus, ParseIntPipe, UseGuards } from '@nestjs/common'
import { ZodSerializerDto } from 'nestjs-zod'
import { SkipThrottle } from '@nestjs/throttler'

import { AuditLog } from 'src/shared/decorators/audit-log.decorator'
import { Roles } from 'src/shared/decorators/roles.decorator'
import { RolesGuard } from 'src/shared/guards/roles.guard'

import { AuditLogService } from './audit-log.service'
import { AuditLogQueryDTO, AuditLogResponseDTO } from './audit-log.dto'
import { ApiException } from 'src/shared/exceptions/api.exception'

@Controller('audit-logs')
@UseGuards(RolesGuard)
export class AuditLogController {
  constructor(private readonly auditLogService: AuditLogService) {}

  @Get()
  @ZodSerializerDto(AuditLogResponseDTO)
  @SkipThrottle()
  @AuditLog({
    action: 'AUDIT_LOG_VIEW_LIST',
    getUserId: ([_, _query, _param, req]) => req?.user?.userId,
    getDetails: ([_, query]) => ({ query })
  })
  @Roles('Admin')
  findAll(@Query() query: AuditLogQueryDTO) {
    return this.auditLogService.findAll(query)
  }

  @Get('stats')
  @SkipThrottle()
  @AuditLog({
    action: 'AUDIT_LOG_VIEW_STATS',
    getUserId: ([_, _query, _param, req]) => req?.user?.userId
  })
  @Roles('Admin')
  getStats() {
    return this.auditLogService.getStats()
  }

  @Get('actions')
  @SkipThrottle()
  @Roles('Admin')
  getActions() {
    return this.auditLogService.getDistinctActions()
  }

  @Get('entities')
  @SkipThrottle()
  @Roles('Admin')
  getEntities() {
    return this.auditLogService.getDistinctEntities()
  }

  @Get(':id')
  @SkipThrottle()
  @AuditLog({
    action: 'AUDIT_LOG_VIEW_DETAIL',
    entity: 'AuditLog',
    getEntityId: ([params]) => Number(params?.id),
    getUserId: ([_, _query, _param, req]) => req?.user?.userId
  })
  @Roles('Admin')
  async findOne(@Param('id', ParseIntPipe) id: number) {
    const log = await this.auditLogService.findById(id)

    if (!log) {
      throw new ApiException(HttpStatus.NOT_FOUND, 'RESOURCE_NOT_FOUND', 'Error.AuditLog.NotFound', [
        { code: 'Error.AuditLog.NotFound', path: 'id', args: { id } }
      ])
    }

    return log
  }
}
