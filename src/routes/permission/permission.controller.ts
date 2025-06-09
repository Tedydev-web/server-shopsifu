import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  ParseIntPipe,
  UsePipes,
  ValidationPipe,
  UseGuards
} from '@nestjs/common'
import { PermissionService } from './permission.service'
import { PermissionsGuard } from '../../shared/guards/permissions.guard'
import { RequiredPermissions } from '../../shared/decorators/required-permissions.decorator'
import { CreatePermissionDto, UpdatePermissionDto, PermissionDto } from './permission.dto'

@Controller('rbac/permissions')
@UseGuards(PermissionsGuard)
export class PermissionController {
  constructor(private readonly permissionService: PermissionService) {}

  @Post()
  @RequiredPermissions({ action: 'CREATE', subject: 'Permission' })
  @UsePipes(new ValidationPipe({ transform: true, whitelist: true }))
  async create(@Body() createPermissionDto: CreatePermissionDto): Promise<PermissionDto> {
    const permission = await this.permissionService.create(createPermissionDto)
    return PermissionDto.fromEntity(permission)
  }

  @Get()
  @RequiredPermissions({ action: 'READ', subject: 'Permission' })
  async findAll(): Promise<PermissionDto[]> {
    const permissions = await this.permissionService.findAll()
    return permissions.map((permission) => PermissionDto.fromEntity(permission))
  }

  @Get(':id')
  @RequiredPermissions({ action: 'READ', subject: 'Permission' })
  async findOne(@Param('id', ParseIntPipe) id: number): Promise<PermissionDto> {
    const permission = await this.permissionService.findOne(id)
    return PermissionDto.fromEntity(permission)
  }

  @Patch(':id')
  @RequiredPermissions({ action: 'UPDATE', subject: 'Permission' })
  @UsePipes(new ValidationPipe({ transform: true, whitelist: true }))
  async update(
    @Param('id', ParseIntPipe) id: number,
    @Body() updatePermissionDto: UpdatePermissionDto
  ): Promise<PermissionDto> {
    const permission = await this.permissionService.update(id, updatePermissionDto)
    return PermissionDto.fromEntity(permission)
  }

  @Delete(':id')
  @RequiredPermissions({ action: 'DELETE', subject: 'Permission' })
  async remove(@Param('id', ParseIntPipe) id: number): Promise<PermissionDto> {
    const permission = await this.permissionService.remove(id)
    return PermissionDto.fromEntity(permission)
  }
}
