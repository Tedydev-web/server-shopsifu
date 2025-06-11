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
import { CanCreateRolePolicy, CanDeleteRolePolicy, CanReadRolePolicy, CanUpdateRolePolicy } from './role.policies'

@Auth()
@UseGuards(PoliciesGuard)
@Controller('role')
export class RoleController {
  constructor(private readonly roleService: RoleService) {}

  @Post()
  @CheckPolicies(...CanCreateRolePolicy)
  @HttpCode(HttpStatus.CREATED)
  async create(@Body() createRoleDto: CreateRoleDto) {
    const role = await this.roleService.create(createRoleDto)
    return new RoleDto(role)
  }

  @Get()
  @CheckPolicies(...CanReadRolePolicy)
  async findAll() {
    const roles = await this.roleService.findAll()
    return roles.map((role) => new RoleDto(role))
  }

  @Get(':id')
  @CheckPolicies(...CanReadRolePolicy)
  async findOne(@Param('id', ParseIntPipe) id: number) {
    const role = await this.roleService.findOne(id)
    return new RoleDto(role)
  }

  @Patch(':id')
  @CheckPolicies(...CanUpdateRolePolicy)
  async update(@Param('id', ParseIntPipe) id: number, @Body() updateRoleDto: UpdateRoleDto) {
    const role = await this.roleService.update(id, updateRoleDto)
    return new RoleDto(role)
  }

  @Delete(':id')
  @CheckPolicies(...CanDeleteRolePolicy)
  @HttpCode(HttpStatus.NO_CONTENT)
  async remove(@Param('id', ParseIntPipe) id: number): Promise<void> {
    await this.roleService.remove(id)
  }
}
