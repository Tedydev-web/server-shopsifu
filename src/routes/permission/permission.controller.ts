import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  ParseIntPipe,
  HttpCode,
  HttpStatus,
  UseGuards,
  Query
} from '@nestjs/common'
import { PermissionService } from './permission.service'
import { CreatePermissionDto, UpdatePermissionDto, PermissionDto, GetPermissionsQueryDto } from './permission.dto'
import { Auth } from 'src/shared/decorators/auth.decorator'
import { PoliciesGuard } from 'src/shared/guards/policies.guard'
import { CheckPolicies } from 'src/shared/decorators/check-policies.decorator'
import { Action, AppAbility } from 'src/shared/providers/casl/casl-ability.factory'
import { PermissionError } from './permission.error'

@Auth()
@UseGuards(PoliciesGuard)
@Controller('permissions')
export class PermissionController {
  constructor(private readonly permissionService: PermissionService) {}

  @Post()
  @CheckPolicies((ability: AppAbility) => ability.can(Action.Create, 'Permission'))
  @HttpCode(HttpStatus.CREATED)
  async create(@Body() createPermissionDto: CreatePermissionDto) {
    const permission = await this.permissionService.create(createPermissionDto)
    return {
      status: HttpStatus.CREATED,
      message: 'permission.success.create',
      data: PermissionDto.fromEntity(permission)
    }
  }

  /**
   * Get all permissions grouped by subject with pagination similar to Sessions module
   */
  @Get()
  @CheckPolicies((ability: AppAbility) => ability.can(Action.Read, 'Permission'))
  async getPermissions(@Query() query: GetPermissionsQueryDto): Promise<any> {
    if (query.page < 1 || query.limit < 1) {
      throw PermissionError.InvalidPagination()
    }

    const result = await this.permissionService.getGroupedPermissions(query.page, query.limit)

    return {
      status: HttpStatus.OK,
      message: result.message,
      data: result.data
    }
  }

  @Get(':id')
  @CheckPolicies((ability: AppAbility) => ability.can(Action.Read, 'Permission'))
  async findOne(@Param('id', ParseIntPipe) id: number) {
    const permission = await this.permissionService.findOne(id)
    return {
      status: HttpStatus.OK,
      message: 'permission.success.get',
      data: PermissionDto.fromEntity(permission)
    }
  }

  @Patch(':id')
  @CheckPolicies((ability: AppAbility) => ability.can(Action.Update, 'Permission'))
  async update(@Param('id', ParseIntPipe) id: number, @Body() updatePermissionDto: UpdatePermissionDto) {
    const permission = await this.permissionService.update(id, updatePermissionDto)
    return {
      status: HttpStatus.OK,
      message: 'permission.success.update',
      data: PermissionDto.fromEntity(permission)
    }
  }

  @Delete(':id')
  @CheckPolicies((ability: AppAbility) => ability.can(Action.Delete, 'Permission'))
  @HttpCode(HttpStatus.OK)
  async remove(@Param('id', ParseIntPipe) id: number) {
    await this.permissionService.remove(id)
    return {
      status: HttpStatus.OK,
      message: 'permission.success.delete'
    }
  }
}
