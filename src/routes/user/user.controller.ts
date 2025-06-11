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
import { Action, AppAbility } from 'src/shared/providers/casl/casl-ability.factory'

@Auth()
@UseGuards(PoliciesGuard)
@Controller('users')
export class UserController {
  constructor(private readonly userService: UserService) {}

  @Post()
  @CheckPolicies((ability: AppAbility) => ability.can(Action.Create, 'User'))
  @HttpCode(HttpStatus.CREATED)
  async create(@Body() createUserDto: CreateUserDto) {
    const user = await this.userService.create(createUserDto)
    return UserDto.fromEntity(user)
  }

  @Get()
  @CheckPolicies((ability: AppAbility) => ability.can(Action.Read, 'User'))
  async findAll() {
    const users = await this.userService.findAll()
    return users.map((user) => UserDto.fromEntity(user))
  }

  @Get(':id')
  @CheckPolicies((ability: AppAbility) => ability.can(Action.Read, 'User'))
  async findOne(@Param('id', ParseIntPipe) id: number) {
    const user = await this.userService.findOne(id)
    return UserDto.fromEntity(user)
  }

  @Patch(':id')
  @CheckPolicies((ability: AppAbility) => ability.can(Action.Update, 'User'))
  async update(@Param('id', ParseIntPipe) id: number, @Body() updateUserDto: UpdateUserDto) {
    const user = await this.userService.update(id, updateUserDto)
    return UserDto.fromEntity(user)
  }

  @Delete(':id')
  @CheckPolicies((ability: AppAbility) => ability.can(Action.Delete, 'User'))
  @HttpCode(HttpStatus.NO_CONTENT)
  async remove(@Param('id', ParseIntPipe) id: number): Promise<void> {
    await this.userService.remove(id)
  }
}
