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
import { CreatePermissionDto, PermissionDto, UpdatePermissionDto } from './permission.dto'
import { PermissionService } from './permission.service'
import { Action, AppSubject } from 'src/shared/providers/casl/casl-ability.factory'
import { Permission } from './permission.model'

@Auth()
@UseGuards(PermissionGuard)
@Controller('permissions')
export class PermissionController {
  constructor(private readonly permissionService: PermissionService) {}

  @Post()
  @RequirePermissions({ action: Action.Create, subject: AppSubject.Permission })
  @HttpCode(HttpStatus.CREATED)
  async create(@Body() createPermissionDto: CreatePermissionDto) {
    const permission = await this.permissionService.create(createPermissionDto)
    return {
      message: 'permission.success.create',
      data: PermissionDto.fromEntity(permission)
    }
  }

  /**
   * Get all permissions grouped by subject for UI.
   * This is not paginated as the UI typically needs all permissions at once for role assignment.
   */
  @Get()
  @RequirePermissions({ action: Action.Read, subject: AppSubject.Permission })
  async getAllGroupedPermissions() {
    const permissions = await this.permissionService.getAllGroupedPermissions()
    return {
      message: 'permission.success.list',
      data: permissions
    }
  }

  @Get(':id')
  @RequirePermissions({ action: Action.Read, subject: Permission })
  async findOne(@Param('id', ParseIntPipe) id: number) {
    const permission = await this.permissionService.findOne(id)
    return {
      message: 'permission.success.get',
      data: PermissionDto.fromEntity(permission)
    }
  }

  @Patch(':id')
  @RequirePermissions({ action: Action.Update, subject: Permission })
  async update(@Param('id', ParseIntPipe) id: number, @Body() updatePermissionDto: UpdatePermissionDto) {
    const permission = await this.permissionService.update(id, updatePermissionDto)
    return {
      message: 'permission.success.update',
      data: PermissionDto.fromEntity(permission)
    }
  }

  @Delete(':id')
  @HttpCode(HttpStatus.NO_CONTENT)
  @RequirePermissions({ action: Action.Delete, subject: Permission })
  async remove(@Param('id', ParseIntPipe) id: number) {
    await this.permissionService.remove(id)
  }
}
