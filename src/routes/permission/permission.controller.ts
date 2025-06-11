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
import { PermissionService } from './permission.service'
import { CreatePermissionDto, UpdatePermissionDto, PermissionDto } from './permission.dto'
import { Auth } from 'src/shared/decorators/auth.decorator'
import { PoliciesGuard } from 'src/shared/guards/policies.guard'
import { CheckPolicies } from 'src/shared/decorators/check-policies.decorator'
import {
  CanCreatePermissionPolicy,
  CanDeletePermissionPolicy,
  CanReadPermissionPolicy,
  CanUpdatePermissionPolicy
} from './permission.policies'

@Auth()
@UseGuards(PoliciesGuard)
@Controller('permissions')
export class PermissionController {
  constructor(private readonly permissionService: PermissionService) {}

  @Post()
  @CheckPolicies(...CanCreatePermissionPolicy)
  @HttpCode(HttpStatus.CREATED)
  async create(@Body() createPermissionDto: CreatePermissionDto) {
    const permission = await this.permissionService.create(createPermissionDto)
    return PermissionDto.fromEntity(permission)
  }

  @Get()
  @CheckPolicies(...CanReadPermissionPolicy)
  async findAll() {
    const permissions = await this.permissionService.findAll()
    return permissions.map((permission) => PermissionDto.fromEntity(permission))
  }

  @Get(':id')
  @CheckPolicies(...CanReadPermissionPolicy)
  async findOne(@Param('id', ParseIntPipe) id: number) {
    const permission = await this.permissionService.findOne(id)
    return PermissionDto.fromEntity(permission)
  }

  @Patch(':id')
  @CheckPolicies(...CanUpdatePermissionPolicy)
  async update(@Param('id', ParseIntPipe) id: number, @Body() updatePermissionDto: UpdatePermissionDto) {
    const permission = await this.permissionService.update(id, updatePermissionDto)
    return PermissionDto.fromEntity(permission)
  }

  @Delete(':id')
  @CheckPolicies(...CanDeletePermissionPolicy)
  @HttpCode(HttpStatus.NO_CONTENT)
  async remove(@Param('id', ParseIntPipe) id: number): Promise<void> {
    await this.permissionService.remove(id)
  }
}
