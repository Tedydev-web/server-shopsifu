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
import { CreateUserDto, UpdateUserDto } from './user.dto'
import { Auth } from 'src/shared/decorators/auth.decorator'
import { PoliciesGuard } from 'src/shared/guards/policies.guard'
import { CheckPolicies } from 'src/shared/decorators/check-policies.decorator'
import { Action, AppAbility } from 'src/shared/casl/casl-ability.factory'

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
    return {
      message: 'user.success.create',
      data: user
    }
  }

  @Get()
  @CheckPolicies((ability: AppAbility) => ability.can(Action.Read, 'User'))
  async findAll() {
    const users = await this.userService.findAll()
    return {
      message: 'user.success.list',
      data: users
    }
  }

  @Get(':id')
  @CheckPolicies((ability: AppAbility) => ability.can(Action.Read, 'User'))
  async findOne(@Param('id', ParseIntPipe) id: number) {
    const user = await this.userService.findOne(id)
    return {
      message: 'user.success.get',
      data: user
    }
  }

  @Patch(':id')
  @CheckPolicies((ability: AppAbility) => ability.can(Action.Update, 'User'))
  async update(@Param('id', ParseIntPipe) id: number, @Body() updateUserDto: UpdateUserDto) {
    const user = await this.userService.update(id, updateUserDto)
    return {
      message: 'user.success.update',
      data: user
    }
  }

  @Delete(':id')
  @CheckPolicies((ability: AppAbility) => ability.can(Action.Delete, 'User'))
  @HttpCode(HttpStatus.OK)
  async remove(@Param('id', ParseIntPipe) id: number) {
    const user = await this.userService.remove(id)
    return {
      message: 'user.success.delete',
      data: user
    }
  }
}
