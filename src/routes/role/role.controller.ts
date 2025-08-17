import { Body, Controller, Delete, Get, Param, Post, Put, Query } from '@nestjs/common'
import { ZodSerializerDto } from 'nestjs-zod'
import {
  CreateRoleBodyDTO,
  CreateRoleResDTO,
  GetRoleDetailResDTO,
  GetRoleParamsDTO,
  GetRolesQueryDTO,
  GetRolesResDTO,
  UpdateRoleBodyDTO
} from 'src/routes/role/role.dto'
import { RoleService } from 'src/routes/role/role.service'
import { ActiveUser } from 'src/shared/decorators/active-user.decorator'
import { MessageResDTO } from 'src/shared/dtos/response.dto'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'

@Controller('roles')
export class RoleController {
  constructor(private readonly roleService: RoleService) {}

  @Get()
  @ZodSerializerDto(GetRolesResDTO)
  list(@Query() query: GetRolesQueryDTO) {
    return this.roleService.list(query)
  }

  @Get(':roleId')
  @ZodSerializerDto(GetRoleDetailResDTO)
  findById(@Param() params: GetRoleParamsDTO) {
    return this.roleService.findById(params.roleId)
  }

  @Post()
  @ZodSerializerDto(CreateRoleResDTO)
  create(@Body() body: CreateRoleBodyDTO, @ActiveUser() user: AccessTokenPayload) {
    return this.roleService.create({ data: body, user } as any)
  }

  @Put(':roleId')
  @ZodSerializerDto(GetRoleDetailResDTO)
  update(@Body() body: UpdateRoleBodyDTO, @Param() params: GetRoleParamsDTO, @ActiveUser() user: AccessTokenPayload) {
    return this.roleService.update({ data: body, id: params.roleId, user } as any)
  }

  @Delete(':roleId')
  @ZodSerializerDto(MessageResDTO)
  delete(@Param() params: GetRoleParamsDTO, @ActiveUser() user: AccessTokenPayload) {
    return this.roleService.delete({ id: params.roleId, user } as any)
  }
}
