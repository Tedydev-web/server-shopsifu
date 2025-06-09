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
  UseGuards // Added
} from '@nestjs/common'
import { RoleService } from './role.service'
import { CreateRoleDto, UpdateRoleDto } from './role.dto'
import { Role } from '@prisma/client'
import { PermissionsGuard } from '../../shared/guards/permissions.guard' // Added
import { RequiredPermissions } from '../../shared/decorators/required-permissions.decorator' // Added

@Controller('rbac/roles')
@UseGuards(PermissionsGuard) // Added
export class RoleController {
  constructor(private readonly roleService: RoleService) {}

  @Post()
  @RequiredPermissions({ action: 'CREATE', subject: 'Role' }) // Added
  @HttpCode(HttpStatus.CREATED)
  async create(@Body() createRoleDto: CreateRoleDto): Promise<Role> {
    return this.roleService.create(createRoleDto)
  }

  @Get()
  @RequiredPermissions({ action: 'READ', subject: 'Role' }) // Added
  async findAll(): Promise<Role[]> {
    return this.roleService.findAll()
  }

  @Get(':id')
  @RequiredPermissions({ action: 'READ', subject: 'Role' }) // Added
  async findOne(@Param('id', ParseIntPipe) id: number): Promise<Role> {
    return this.roleService.findOne(id)
  }

  @Patch(':id')
  @RequiredPermissions({ action: 'UPDATE', subject: 'Role' }) // Added
  async update(@Param('id', ParseIntPipe) id: number, @Body() updateRoleDto: UpdateRoleDto): Promise<Role> {
    return this.roleService.update(id, updateRoleDto)
  }

  @Delete(':id')
  @RequiredPermissions({ action: 'DELETE', subject: 'Role' }) // Added
  @HttpCode(HttpStatus.OK)
  async remove(@Param('id', ParseIntPipe) id: number): Promise<Role> {
    return this.roleService.remove(id)
  }
}
