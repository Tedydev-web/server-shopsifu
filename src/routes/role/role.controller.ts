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
import { Auth } from 'src/shared/decorators/auth.decorator'
import { RequirePermissions } from 'src/shared/decorators/permissions.decorator'
import { PermissionGuard } from 'src/shared/guards/permission.guard'
import { CreateRoleDto, RoleDto, UpdateRoleDto } from './role.dto'
import { RoleService } from './role.service'

@Auth()
@UseGuards(PermissionGuard)
@Controller('roles')
export class RoleController {
  constructor(private readonly roleService: RoleService) {}

  @Post()
  @RequirePermissions(['Role:create'])
  async create(@Body() createRoleDto: CreateRoleDto) {
    const role = await this.roleService.create(createRoleDto)
    return {
      message: 'Role created successfully',
      data: RoleDto.fromEntity(role)
    }
  }

  @Get()
  @RequirePermissions(['Role:read'])
  async findAll() {
    const roles = await this.roleService.findAll()
    return {
      message: 'Roles retrieved successfully',
      data: roles.map((role) => RoleDto.fromEntity(role))
    }
  }

  @Get(':id')
  @RequirePermissions(['Role:read'])
  async findOne(@Param('id', ParseIntPipe) id: number) {
    const role = await this.roleService.findOne(id)
    return {
      message: 'Role retrieved successfully',
      data: RoleDto.fromEntity(role)
    }
  }

  @Patch(':id')
  @RequirePermissions(['Role:update'])
  async update(@Param('id', ParseIntPipe) id: number, @Body() updateRoleDto: UpdateRoleDto) {
    const role = await this.roleService.update(id, updateRoleDto)
    return {
      message: 'Role updated successfully',
      data: RoleDto.fromEntity(role)
    }
  }

  @Delete(':id')
  @RequirePermissions(['Role:delete'])
  async remove(@Param('id', ParseIntPipe) id: number): Promise<{ message: string }> {
    await this.roleService.remove(id)
    return { message: 'Role deleted successfully' }
  }
}
