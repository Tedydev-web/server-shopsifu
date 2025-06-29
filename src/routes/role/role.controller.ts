import { Controller, Get, Post, Put, Delete, Body, Param, Query, UseGuards } from '@nestjs/common'
import { ZodSerializerDto } from 'nestjs-zod'
import {
  CreateRoleBodyDTO,
  CreateRoleResDTO,
  DeleteRoleResDTO,
  GetRoleDetailResDTO,
  GetRoleParamsDTO,
  GetRolesResDTO,
  RolePaginationQueryDTO,
  UpdateRoleBodyDTO,
  UpdateRoleResDTO,
} from './role.dto'
import { RoleService } from 'src/routes/role/role.service'
import { ActiveUser } from 'src/shared/decorators/active-user.decorator'
import {
  RequirePermissions,
  RequireRead,
  RequireCreate,
  RequireUpdate,
  RequireDelete,
} from 'src/shared/decorators/permission.decorator'
import { PermissionGuard } from 'src/shared/guards/permission.guard'

@Controller('roles')
@UseGuards(PermissionGuard)
export class RoleController {
  constructor(private readonly roleService: RoleService) {}

  @Get()
  @RequireRead('role')
  @ZodSerializerDto(GetRolesResDTO)
  list(@Query() query: RolePaginationQueryDTO) {
    return this.roleService.list({
      page: query.page,
      limit: query.limit,
      sortOrder: query.sortOrder,
      sortBy: query.sortBy,
      search: query.search,
    })
  }

  @Get(':roleId')
  @RequireRead('role')
  @ZodSerializerDto(GetRoleDetailResDTO)
  findById(@Param() params: GetRoleParamsDTO) {
    return this.roleService.findById(params.roleId)
  }

  @Post()
  @RequireCreate('role')
  @ZodSerializerDto(CreateRoleResDTO)
  create(@Body() body: CreateRoleBodyDTO, @ActiveUser('userId') userId: number) {
    return this.roleService.create({
      data: body,
      createdById: userId,
    })
  }

  @Put(':roleId')
  @RequireUpdate('role')
  @ZodSerializerDto(UpdateRoleResDTO)
  update(@Body() body: UpdateRoleBodyDTO, @Param() params: GetRoleParamsDTO, @ActiveUser('userId') userId: number) {
    return this.roleService.update({
      id: params.roleId,
      data: body,
      updatedById: userId,
    })
  }

  @Delete(':roleId')
  @RequireDelete('role')
  @ZodSerializerDto(DeleteRoleResDTO)
  delete(@Param() params: GetRoleParamsDTO, @ActiveUser('userId') userId: number) {
    return this.roleService.delete({
      id: params.roleId,
      deletedById: userId,
    })
  }
}
