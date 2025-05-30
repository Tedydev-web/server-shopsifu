import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  Logger,
  Param,
  Post,
  Put,
  Query,
  UseGuards
} from '@nestjs/common'
import { ZodSerializerDto } from 'nestjs-zod'
import {
  CreatePermissionBodyDTO,
  GetPermissionDetailResDTO,
  GetPermissionParamsDTO,
  GetPermissionsQueryDTO,
  GetPermissionsResDTO,
  RestorePermissionBodyDTO,
  UpdatePermissionBodyDTO
} from 'src/routes/permission/permission.dto'
import { PermissionService } from 'src/routes/permission/permission.service'
import { ActiveUser } from '../auth/decorators/active-user.decorator'
import { MessageResDTO } from 'src/shared/dtos/response.dto'
import { SkipThrottle, Throttle } from '@nestjs/throttler'
import { Roles } from '../auth/decorators/roles.decorator'
import { RolesGuard } from '../auth/guards/roles.guard'

@Controller('permissions')
@UseGuards(RolesGuard)
export class PermissionController {
  private readonly logger = new Logger(PermissionController.name)

  constructor(private readonly permissionService: PermissionService) {}

  @Get()
  @ZodSerializerDto(GetPermissionsResDTO)
  @SkipThrottle()
  @Roles('Admin')
  findAll(@Query() query: GetPermissionsQueryDTO) {
    this.logger.debug(`Finding all permissions with query: ${JSON.stringify(query)}`)
    return this.permissionService.findAll(query)
  }

  @Get(':permissionId')
  @ZodSerializerDto(GetPermissionDetailResDTO)
  @SkipThrottle()
  @Roles('Admin')
  findById(@Param() params: GetPermissionParamsDTO, @Query('includeDeleted') includeDeleted?: boolean) {
    this.logger.debug(`Finding permission by ID: ${params.permissionId}, includeDeleted: ${includeDeleted}`)
    return this.permissionService.findById(params.permissionId, includeDeleted)
  }

  @Post()
  @ZodSerializerDto(GetPermissionDetailResDTO)
  // @Throttle({ short: { limit: 5, ttl: 10000 } })
  @Roles('Admin')
  create(@Body() body: CreatePermissionBodyDTO, @ActiveUser('userId') userId: number) {
    this.logger.debug(`Creating permission: ${JSON.stringify(body)}`)
    return this.permissionService.create({
      data: body,
      createdById: userId
    })
  }

  @Put(':permissionId')
  @ZodSerializerDto(GetPermissionDetailResDTO)
  // @Throttle({ short: { limit: 10, ttl: 10000 } })
  @Roles('Admin')
  update(
    @Body() body: UpdatePermissionBodyDTO,
    @Param() params: GetPermissionParamsDTO,
    @ActiveUser('userId') userId: number
  ) {
    this.logger.debug(`Updating permission ${params.permissionId}: ${JSON.stringify(body)}`)
    return this.permissionService.update({
      data: body,
      id: params.permissionId,
      updatedById: userId
    })
  }

  @Delete(':permissionId')
  @ZodSerializerDto(MessageResDTO)
  // @Throttle({ short: { limit: 5, ttl: 10000 } })
  @Roles('Admin')
  delete(
    @Param() params: GetPermissionParamsDTO,
    @ActiveUser('userId') userId: number,
    @Query('hardDelete') hardDelete?: boolean
  ) {
    this.logger.debug(`Deleting permission ${params.permissionId}, hardDelete: ${hardDelete}`)
    return this.permissionService.delete(params.permissionId, userId, hardDelete)
  }

  @Post(':permissionId/restore')
  @HttpCode(HttpStatus.OK)
  @ZodSerializerDto(GetPermissionDetailResDTO)
  // @Throttle({ short: { limit: 5, ttl: 10000 } })
  @Roles('Admin')
  restore(
    @Param() params: GetPermissionParamsDTO,
    @Body() _: RestorePermissionBodyDTO,
    @ActiveUser('userId') userId: number
  ) {
    this.logger.debug(`Restoring permission ${params.permissionId}`)
    return this.permissionService.restore(params.permissionId, userId)
  }
}
