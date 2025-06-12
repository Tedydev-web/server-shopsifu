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
import { Auth } from 'src/shared/decorators/auth.decorator'
import { RequirePermissions } from 'src/shared/decorators/permissions.decorator'
import { PermissionGuard } from 'src/shared/guards/permission.guard'
import { CreatePermissionDto, PermissionDto, UpdatePermissionDto } from './permission.dto'
import { PermissionService } from './permission.service'
import { Action, AppSubject } from 'src/shared/casl/casl-ability.factory'
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
      message: 'Permission created successfully',
      data: PermissionDto.fromEntity(permission)
    }
  }

  /**
   * Get all permissions grouped by subject for UI.
   * This is not paginated as the UI typically needs all permissions at once for role assignment.
   */
  @Get()
  @RequirePermissions({ action: Action.Read, subject: AppSubject.Role })
  async getAllGroupedPermissions() {
    const permissions = await this.permissionService.getAllGroupedPermissions()
    return {
      message: 'Permissions retrieved successfully',
      data: permissions
    }
  }

  @Get(':id')
  @RequirePermissions({ action: Action.Read, subject: Permission })
  async findOne(@Param('id', ParseIntPipe) id: number) {
    const permission = await this.permissionService.findOne(id)
    return {
      message: 'Permission retrieved successfully',
      data: PermissionDto.fromEntity(permission)
    }
  }

  @Patch(':id')
  @RequirePermissions({ action: Action.Update, subject: Permission })
  async update(@Param('id', ParseIntPipe) id: number, @Body() updatePermissionDto: UpdatePermissionDto) {
    const permission = await this.permissionService.update(id, updatePermissionDto)
    return {
      message: 'Permission updated successfully',
      data: PermissionDto.fromEntity(permission)
    }
  }

  @Delete(':id')
  @RequirePermissions({ action: Action.Delete, subject: Permission })
  @HttpCode(HttpStatus.NO_CONTENT)
  async remove(@Param('id', ParseIntPipe) id: number) {
    await this.permissionService.remove(id)
  }
}
