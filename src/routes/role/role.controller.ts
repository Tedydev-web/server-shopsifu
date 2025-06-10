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
import { RoleService } from './role.service'
import { CreateRoleDto, UpdateRoleDto, RoleDto } from './role.dto'
import { Auth } from 'src/shared/decorators/auth.decorator'
import { PoliciesGuard } from 'src/shared/guards/policies.guard'
import { CheckPolicies } from 'src/shared/decorators/check-policies.decorator'
import { Action, AppAbility } from 'src/shared/casl/casl-ability.factory'

@Auth()
@UseGuards(PoliciesGuard)
@Controller('roles')
export class RoleController {
  constructor(private readonly roleService: RoleService) {}

  @Post()
  @CheckPolicies((ability: AppAbility) => ability.can(Action.Create, 'Role'))
  @HttpCode(HttpStatus.CREATED)
  async create(@Body() createRoleDto: CreateRoleDto) {
    const role = await this.roleService.create(createRoleDto)
    return {
      message: 'role.success.create',
      data: new RoleDto(role)
    }
  }

  @Get()
  @CheckPolicies((ability: AppAbility) => ability.can(Action.Read, 'Role'))
  async findAll() {
    const roles = await this.roleService.findAll()
    return {
      message: 'role.success.list',
      data: roles.map((role) => new RoleDto(role))
    }
  }

  @Get(':id')
  @CheckPolicies((ability: AppAbility) => ability.can(Action.Read, 'Role'))
  async findOne(@Param('id', ParseIntPipe) id: number) {
    const role = await this.roleService.findOne(id)
    return {
      message: 'role.success.get',
      data: new RoleDto(role)
    }
  }

  @Patch(':id')
  @CheckPolicies((ability: AppAbility) => ability.can(Action.Update, 'Role'))
  async update(@Param('id', ParseIntPipe) id: number, @Body() updateRoleDto: UpdateRoleDto) {
    const role = await this.roleService.update(id, updateRoleDto)
    return {
      message: 'role.success.update',
      data: new RoleDto(role)
    }
  }

  @Delete(':id')
  @CheckPolicies((ability: AppAbility) => ability.can(Action.Delete, 'Role'))
  @HttpCode(HttpStatus.OK)
  async remove(@Param('id', ParseIntPipe) id: number) {
    const role = await this.roleService.remove(id)
    return {
      message: 'role.success.delete',
      data: new RoleDto(role)
    }
  }
}
