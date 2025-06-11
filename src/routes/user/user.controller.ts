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
import { UserService } from './user.service'
import { CreateUserDto, UpdateUserDto, UserDto } from './user.dto'
import { Auth } from 'src/shared/decorators/auth.decorator'
import { PoliciesGuard } from 'src/shared/guards/policies.guard'
import { CheckPolicies } from 'src/shared/decorators/check-policies.decorator'
import { CanCreateUserPolicy, CanDeleteUserPolicy, CanReadUserPolicy, CanUpdateUserPolicy } from './user.policies'

@Auth()
@UseGuards(PoliciesGuard)
@Controller('users')
export class UserController {
  constructor(private readonly userService: UserService) {}

  @Post()
  @CheckPolicies(...CanCreateUserPolicy)
  @HttpCode(HttpStatus.CREATED)
  async create(@Body() createUserDto: CreateUserDto) {
    const user = await this.userService.create(createUserDto)
    return UserDto.fromEntity(user)
  }

  @Get()
  @CheckPolicies(...CanReadUserPolicy)
  async findAll() {
    const users = await this.userService.findAll()
    return users.map((user) => UserDto.fromEntity(user))
  }

  @Get(':id')
  @CheckPolicies(...CanReadUserPolicy)
  async findOne(@Param('id', ParseIntPipe) id: number) {
    const user = await this.userService.findOne(id)
    return UserDto.fromEntity(user)
  }

  @Patch(':id')
  @CheckPolicies(...CanUpdateUserPolicy)
  async update(@Param('id', ParseIntPipe) id: number, @Body() updateUserDto: UpdateUserDto) {
    const user = await this.userService.update(id, updateUserDto)
    return UserDto.fromEntity(user)
  }

  @Delete(':id')
  @CheckPolicies(...CanDeleteUserPolicy)
  @HttpCode(HttpStatus.NO_CONTENT)
  async remove(@Param('id', ParseIntPipe) id: number): Promise<void> {
    await this.userService.remove(id)
  }
}
