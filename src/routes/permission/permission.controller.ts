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
import { GetPermissionsQueryDto, CreatePermissionDto, UpdatePermissionDto, PermissionDto } from './permission.dto'
import { Auth } from 'src/shared/decorators/auth.decorator'
import { PermissionGuard } from 'src/shared/guards/permission.guard'
import { RequirePermissions } from 'src/shared/decorators/permissions.decorator'

@Auth()
@UseGuards(PermissionGuard)
@Controller('permissions')
export class PermissionController {
  constructor(private readonly permissionService: PermissionService) {}

  @Post()
  @RequirePermissions(['Permission:create'])
  @HttpCode(HttpStatus.CREATED)
  async create(@Body() createPermissionDto: CreatePermissionDto) {
    const permission = await this.permissionService.create(createPermissionDto)
    return {
      message: 'Permission created successfully',
      data: PermissionDto.fromEntity(permission)
    }
  }

  /**
   * Get all permissions grouped by subject with pagination similar to Sessions module
   */
  @Get()
  @RequirePermissions(['Permission:read'])
  async getPermissions(@Query() query: GetPermissionsQueryDto): Promise<any> {
    const { page, limit } = query
    return await this.permissionService.getGroupedPermissions(page, limit)
  }

  @Get(':id')
  @RequirePermissions(['Permission:read'])
  async findOne(@Param('id', ParseIntPipe) id: number) {
    const permission = await this.permissionService.findOne(id)
    return {
      message: 'Permission retrieved successfully',
      data: PermissionDto.fromEntity(permission)
    }
  }

  @Patch(':id')
  @RequirePermissions(['Permission:update'])
  async update(@Param('id', ParseIntPipe) id: number, @Body() updatePermissionDto: UpdatePermissionDto) {
    const permission = await this.permissionService.update(id, updatePermissionDto)
    return {
      message: 'Permission updated successfully',
      data: PermissionDto.fromEntity(permission)
    }
  }

  @Delete(':id')
  @RequirePermissions(['Permission:delete'])
  @HttpCode(HttpStatus.NO_CONTENT)
  async remove(@Param('id', ParseIntPipe) id: number) {
    await this.permissionService.remove(id)
  }
}
