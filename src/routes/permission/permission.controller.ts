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
  UseGuards
} from '@nestjs/common'
import { PermissionService } from './permission.service'
import { CreatePermissionDto, UpdatePermissionDto, PermissionDto } from './permission.dto'
import { Auth } from 'src/shared/decorators/auth.decorator'
import { PoliciesGuard } from 'src/shared/guards/policies.guard'
import { CheckPolicies } from 'src/shared/decorators/check-policies.decorator'
import { Action, AppAbility } from 'src/shared/casl/casl-ability.factory'

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
      message: 'permission.success.create',
      data: PermissionDto.fromEntity(permission)
    }
  }

  @Get()
  @CheckPolicies((ability: AppAbility) => ability.can(Action.Read, 'Permission'))
  async findAll() {
    const permissions = await this.permissionService.findAll()
    return {
      message: 'permission.success.list',
      data: permissions.map((permission) => PermissionDto.fromEntity(permission))
    }
  }

  @Get(':id')
  @CheckPolicies((ability: AppAbility) => ability.can(Action.Read, 'Permission'))
  async findOne(@Param('id', ParseIntPipe) id: number) {
    const permission = await this.permissionService.findOne(id)
    return {
      message: 'permission.success.get',
      data: PermissionDto.fromEntity(permission)
    }
  }

  @Patch(':id')
  @CheckPolicies((ability: AppAbility) => ability.can(Action.Update, 'Permission'))
  async update(@Param('id', ParseIntPipe) id: number, @Body() updatePermissionDto: UpdatePermissionDto) {
    const permission = await this.permissionService.update(id, updatePermissionDto)
    return {
      message: 'permission.success.update',
      data: PermissionDto.fromEntity(permission)
    }
  }

  @Delete(':id')
  @CheckPolicies((ability: AppAbility) => ability.can(Action.Delete, 'Permission'))
  @HttpCode(HttpStatus.OK)
  async remove(@Param('id', ParseIntPipe) id: number) {
    const permission = await this.permissionService.remove(id)
    return {
      message: 'permission.success.delete',
      data: PermissionDto.fromEntity(permission)
    }
  }
}
