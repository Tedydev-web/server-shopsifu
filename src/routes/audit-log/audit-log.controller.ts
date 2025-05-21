import { Controller, Get, Query, Param, HttpStatus, ParseIntPipe } from '@nestjs/common'
import { ZodSerializerDto } from 'nestjs-zod'
import { SkipThrottle } from '@nestjs/throttler'
import { Auth } from 'src/shared/decorators/auth.decorator'
import { AuthType } from 'src/shared/constants/auth.constant'
import { ActiveUser } from 'src/shared/decorators/active-user.decorator'
import { AuditLog } from 'src/shared/decorators/audit-log.decorator'

import { AuditLogService } from './audit-log.service'
import { AuditLogQueryDTO, AuditLogResponseDTO } from './audit-log.dto'
import { ApiException } from 'src/shared/exceptions/api.exception'
import { RoleName } from 'src/shared/constants/role.constant'

@Controller('audit-logs')
@Auth([AuthType.Bearer])
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
  findAll(@Query() query: AuditLogQueryDTO, @ActiveUser('roleName') roleName: string) {
    if (roleName !== RoleName.Admin) {
      throw new ApiException(HttpStatus.FORBIDDEN, 'FORBIDDEN', 'Error.AuditLog.AccessDenied')
    }

    return this.auditLogService.findAll(query)
  }

  @Get('stats')
  @SkipThrottle()
  @AuditLog({
    action: 'AUDIT_LOG_VIEW_STATS',
    getUserId: ([_, _query, _param, req]) => req?.user?.userId
  })
  getStats(@ActiveUser('roleName') roleName: string) {
    if (roleName !== RoleName.Admin) {
      throw new ApiException(HttpStatus.FORBIDDEN, 'FORBIDDEN', 'Error.AuditLog.AccessDenied')
    }

    return this.auditLogService.getStats()
  }

  @Get('actions')
  @SkipThrottle()
  getActions(@ActiveUser('roleName') roleName: string) {
    if (roleName !== RoleName.Admin) {
      throw new ApiException(HttpStatus.FORBIDDEN, 'FORBIDDEN', 'Error.AuditLog.AccessDenied')
    }

    return this.auditLogService.getDistinctActions()
  }

  @Get('entities')
  @SkipThrottle()
  getEntities(@ActiveUser('roleName') roleName: string) {
    if (roleName !== RoleName.Admin) {
      throw new ApiException(HttpStatus.FORBIDDEN, 'FORBIDDEN', 'Error.AuditLog.AccessDenied')
    }

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
  async findOne(@Param('id', ParseIntPipe) id: number, @ActiveUser('roleName') roleName: string) {
    if (roleName !== RoleName.Admin) {
      throw new ApiException(HttpStatus.FORBIDDEN, 'FORBIDDEN', 'Error.AuditLog.AccessDenied')
    }

    const log = await this.auditLogService.findById(id)

    if (!log) {
      throw new ApiException(HttpStatus.NOT_FOUND, 'RESOURCE_NOT_FOUND', 'Error.AuditLog.NotFound', [
        { code: 'Error.AuditLog.NotFound', path: 'id', args: { id } }
      ])
    }

    return log
  }
}
