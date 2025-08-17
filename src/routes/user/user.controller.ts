import { Body, Controller, Delete, Get, Param, Post, Put, Query } from '@nestjs/common'
import { ZodSerializerDto } from 'nestjs-zod'
import {
  CreateUserBodyDTO,
  CreateUserResDTO,
  GetUserParamsDTO,
  GetUsersQueryDTO,
  GetUsersResDTO,
  UpdateUserBodyDTO
} from 'src/routes/user/user.dto'
import { UserService } from 'src/routes/user/user.service'
import { ActiveRolePermissions } from 'src/shared/decorators/active-role-permissions.decorator'
import { ActiveUser } from 'src/shared/decorators/active-user.decorator'
import { MessageResDTO } from 'src/shared/dtos/response.dto'
import { GetUserProfileResDTO, UpdateProfileResDTO } from 'src/shared/dtos/shared-user.dto'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'

@Controller('users')
export class UserController {
  constructor(private readonly userService: UserService) {}

  @Get()
  @ZodSerializerDto(GetUsersResDTO)
  list(@Query() query: GetUsersQueryDTO) {
    return this.userService.list({
      page: query.page,
      limit: query.limit
    })
  }

  @Get(':userId')
  @ZodSerializerDto(GetUserProfileResDTO)
  findById(@Param() params: GetUserParamsDTO) {
    return this.userService.findById(params.userId)
  }

  @Post()
  @ZodSerializerDto(CreateUserResDTO)
  create(
    @Body() body: CreateUserBodyDTO,
    @ActiveUser() user: AccessTokenPayload,
    @ActiveRolePermissions('name') roleName: string
  ) {
    return this.userService.create({
      data: body,
      user,
      roleName
    } as any)
  }

  @Put(':userId')
  @ZodSerializerDto(UpdateProfileResDTO)
  update(
    @Body() body: UpdateUserBodyDTO,
    @Param() params: GetUserParamsDTO,
    @ActiveUser() user: AccessTokenPayload,
    @ActiveRolePermissions('name') roleName: string
  ) {
    return this.userService.update({
      data: body,
      id: params.userId,
      user,
      roleName
    })
  }

  @Delete(':userId')
  @ZodSerializerDto(MessageResDTO)
  delete(
    @Param() params: GetUserParamsDTO,
    @ActiveUser() user: AccessTokenPayload,
    @ActiveRolePermissions('name') roleName: string
  ) {
    return this.userService.delete({
      id: params.userId,
      user,
      roleName
    })
  }
}
