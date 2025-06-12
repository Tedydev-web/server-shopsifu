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
import { Action, AppSubject } from 'src/shared/casl/casl-ability.factory'
import { Role } from './role.model'

@Auth()
@UseGuards(PermissionGuard)
@Controller('roles')
export class RoleController {
  constructor(private readonly roleService: RoleService) {}

  @Post()
  @RequirePermissions({ action: Action.Create, subject: AppSubject.Role })
  async create(@Body() createRoleDto: CreateRoleDto) {
    const role = await this.roleService.create(createRoleDto)
    return {
      message: 'Role created successfully',
      data: RoleDto.fromEntity(role)
    }
  }

  @Get()
  @RequirePermissions({ action: Action.Read, subject: AppSubject.Role })
  async findAll() {
    const roles = await this.roleService.findAll()
    return {
      message: 'Roles retrieved successfully',
      data: roles.map((role) => RoleDto.fromEntity(role))
    }
  }

  @Get(':id')
  @RequirePermissions({ action: Action.Read, subject: Role })
  async findOne(@Param('id', ParseIntPipe) id: number) {
    const role = await this.roleService.findOne(id)
    return {
      message: 'Role retrieved successfully',
      data: RoleDto.fromEntity(role)
    }
  }

  @Patch(':id')
  @RequirePermissions({ action: Action.Update, subject: Role })
  async update(@Param('id', ParseIntPipe) id: number, @Body() updateRoleDto: UpdateRoleDto) {
    const role = await this.roleService.update(id, updateRoleDto)
    return {
      message: 'Role updated successfully',
      data: RoleDto.fromEntity(role)
    }
  }

  @Delete(':id')
  @RequirePermissions({ action: Action.Delete, subject: Role })
  async remove(@Param('id', ParseIntPipe) id: number): Promise<{ message: string }> {
    await this.roleService.remove(id)
    return { message: 'Role deleted successfully' }
  }
}
