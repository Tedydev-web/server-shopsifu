import { Body, Controller, Delete, Get, Param, Post, Put, Query } from '@nestjs/common'
import { ZodSerializerDto } from 'nestjs-zod'
import {
  CreatePermissionBodyDTO,
  GetPermissionDetailResDTO,
  GetPermissionParamsDTO,
  PermissionPaginationQueryDTO,
  GetPermissionsResDTO,
  UpdatePermissionBodyDTO,
} from 'src/routes/permission/permission.dto'
import { PermissionService } from 'src/routes/permission/permission.service'
import { ActiveUser } from 'src/shared/decorators/active-user.decorator'
import { RequireCreate, RequireDelete, RequireRead, RequireUpdate } from 'src/shared/decorators/permission.decorator'
import { MessageResponseDTO } from 'src/shared/dtos/core.dto'

@Controller('permissions')
export class PermissionController {
  constructor(private readonly permissionService: PermissionService) {}

  @Get()
  @RequireRead('permission')
  @ZodSerializerDto(GetPermissionsResDTO)
  list(@Query() query: PermissionPaginationQueryDTO) {
    return this.permissionService.list({
      page: query.page,
      limit: query.limit,
      sortOrder: query.sortOrder,
      sortBy: query.sortBy,
      search: query.search,
    })
  }

  @Get(':permissionId')
  @RequireRead('permission')
  @ZodSerializerDto(GetPermissionDetailResDTO)
  findById(@Param() params: GetPermissionParamsDTO) {
    return this.permissionService.findById(params.permissionId)
  }

  @Post()
  @RequireCreate('permission')
  @ZodSerializerDto(GetPermissionDetailResDTO)
  create(@Body() body: CreatePermissionBodyDTO, @ActiveUser('userId') userId: number) {
    return this.permissionService.create({
      data: body,
      createdById: userId,
    })
  }

  @Put(':permissionId')
  @RequireUpdate('permission')
  @ZodSerializerDto(GetPermissionDetailResDTO)
  update(
    @Body() body: UpdatePermissionBodyDTO,
    @Param() params: GetPermissionParamsDTO,
    @ActiveUser('userId') userId: number,
  ) {
    return this.permissionService.update({
      data: body,
      id: params.permissionId,
      updatedById: userId,
    })
  }

  @Delete(':permissionId')
  @RequireDelete('permission')
  @ZodSerializerDto(MessageResponseDTO)
  delete(@Param() params: GetPermissionParamsDTO, @ActiveUser('userId') userId: number) {
    return this.permissionService.delete({
      id: params.permissionId,
      deletedById: userId,
    })
  }
}
