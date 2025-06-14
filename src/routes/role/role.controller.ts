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
import { CreateRoleDto, UpdateRoleDto } from './role.dto'
import { RoleService } from './role.service'
import { Action, AppSubject } from 'src/shared/providers/casl/casl-ability.factory'

@Auth()
@UseGuards(PermissionGuard)
@Controller('roles')
export class RoleController {
  constructor(private readonly roleService: RoleService) {}

  @Post()
  @RequirePermissions({ action: Action.Create, subject: AppSubject.Role })
  async create(@Body() createRoleDto: CreateRoleDto) {
    const data = await this.roleService.create(createRoleDto)
    return {
      message: 'role.success.create',
      data
    }
  }

  @Get()
  @RequirePermissions({ action: Action.Read, subject: AppSubject.Role })
  async findAll() {
    const data = await this.roleService.findAll()
    return {
      message: 'role.success.list',
      data
    }
  }

  @Get(':id')
  @RequirePermissions({ action: Action.Read, subject: AppSubject.Role })
  async findOne(@Param('id', ParseIntPipe) id: number) {
    const data = await this.roleService.findOne(id)
    return {
      message: 'role.success.get',
      data
    }
  }

  @Patch(':id')
  @RequirePermissions({ action: Action.Update, subject: AppSubject.Role })
  async update(@Param('id', ParseIntPipe) id: number, @Body() updateRoleDto: UpdateRoleDto) {
    const data = await this.roleService.update(id, updateRoleDto)
    return {
      message: 'role.success.update',
      data
    }
  }

  @Delete(':id')
  @HttpCode(HttpStatus.OK)
  @RequirePermissions({ action: Action.Delete, subject: AppSubject.Role })
  async remove(@Param('id', ParseIntPipe) id: number) {
    await this.roleService.remove(id)
    return {
      message: 'role.success.delete'
    }
  }
}
