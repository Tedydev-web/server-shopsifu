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
  CreateRoleBodyDTO,
  GetRoleDetailResDTO,
  GetRoleParamsDTO,
  GetRolesQueryDTO,
  GetRolesResDTO,
  RestoreRoleBodyDTO,
  UpdateRoleBodyDTO,
  AssignPermissionsToRoleBodyDTO
} from 'src/routes/role/role.dto'
import { RoleService } from 'src/routes/role/role.service'
import { ActiveUser } from '../auth/decorators/active-user.decorator'
import { MessageResDTO } from 'src/shared/dtos/response.dto'
import { SkipThrottle, Throttle } from '@nestjs/throttler'
import { Roles } from 'src/routes/auth/decorators/roles.decorator'
import { RolesGuard } from '../auth/guards/roles.guard'

@Controller('roles')
@UseGuards(RolesGuard)
export class RoleController {
  private readonly logger = new Logger(RoleController.name)

  constructor(private readonly roleService: RoleService) {}

  @Get()
  @ZodSerializerDto(GetRolesResDTO)
  @SkipThrottle()
  @Roles('Admin')
  findAll(@Query() query: GetRolesQueryDTO) {
    this.logger.debug(`Finding all roles with query: ${JSON.stringify(query)}`)
    return this.roleService.findAll(query)
  }

  @Get(':roleId')
  @ZodSerializerDto(GetRoleDetailResDTO)
  @SkipThrottle()
  @Roles('Admin')
  findById(@Param() params: GetRoleParamsDTO, @Query('includeDeleted') includeDeleted?: boolean) {
    this.logger.debug(`Finding role by ID: ${params.roleId}, includeDeleted: ${includeDeleted}`)
    return this.roleService.findById(params.roleId, includeDeleted)
  }

  @Post()
  @ZodSerializerDto(GetRoleDetailResDTO)
  // @Throttle({ short: { limit: 5, ttl: 10000 } })
  @Roles('Admin')
  create(@Body() body: CreateRoleBodyDTO, @ActiveUser('userId') userId: number) {
    this.logger.debug(`Creating role: ${JSON.stringify(body)} by user ${userId}`)
    return this.roleService.create({
      data: body,
      createdById: userId
    })
  }

  @Put(':roleId')
  @ZodSerializerDto(GetRoleDetailResDTO)
  // @Throttle({ short: { limit: 10, ttl: 10000 } })
  @Roles('Admin')
  update(@Body() body: UpdateRoleBodyDTO, @Param() params: GetRoleParamsDTO, @ActiveUser('userId') userId: number) {
    this.logger.debug(`Updating role ${params.roleId}: ${JSON.stringify(body)} by user ${userId}`)
    return this.roleService.update({
      data: body,
      id: params.roleId,
      updatedById: userId
    })
  }

  @Post(':roleId/assign-permissions')
  @ZodSerializerDto(GetRoleDetailResDTO)
  // @Throttle({ short: { limit: 10, ttl: 10000 } })
  @Roles('Admin')
  assignPermissions(
    @Param() params: GetRoleParamsDTO,
    @Body() body: AssignPermissionsToRoleBodyDTO,
    @ActiveUser('userId') userId: number
  ) {
    this.logger.debug(
      `Assigning permissions ${JSON.stringify(body.permissionIds)} to role ${params.roleId} by user ${userId}`
    )
    return this.roleService.assignPermissions({
      roleId: params.roleId,
      data: body,
      updatedById: userId
    })
  }

  @Delete(':roleId')
  @HttpCode(HttpStatus.OK)
  @ZodSerializerDto(MessageResDTO)
  // @Throttle({ short: { limit: 5, ttl: 10000 } })
  @Roles('Admin')
  delete(
    @Param() params: GetRoleParamsDTO,
    @ActiveUser('userId') userId: number,
    @Query('hardDelete') hardDelete?: boolean
  ) {
    this.logger.debug(`Deleting role ${params.roleId}, hardDelete: ${hardDelete} by user ${userId}`)
    return this.roleService.delete(params.roleId, userId, hardDelete)
  }

  @Post(':roleId/restore')
  @HttpCode(HttpStatus.OK)
  @ZodSerializerDto(GetRoleDetailResDTO)
  // @Throttle({ short: { limit: 5, ttl: 10000 } })
  @Roles('Admin')
  restore(@Param() params: GetRoleParamsDTO, @Body() _: RestoreRoleBodyDTO, @ActiveUser('userId') userId: number) {
    this.logger.debug(`Restoring role ${params.roleId} by user ${userId}`)
    return this.roleService.restore(params.roleId, userId)
  }
}
