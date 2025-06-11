// ================================================================
// NestJS Dependencies
// ================================================================
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

// ================================================================
// Internal Services & Types
// ================================================================
import { UserService } from './user.service'
import { CreateUserDto, UpdateUserDto, UserDto } from './user.dto'

// ================================================================
// Decorators & Guards
// ================================================================
import { Auth } from 'src/shared/decorators/auth.decorator'
import { PoliciesGuard } from 'src/shared/guards/policies.guard'
import { CheckPolicies } from 'src/shared/decorators/check-policies.decorator'
import { Action, AppAbility } from 'src/shared/providers/casl/casl-ability.factory'

/**
 * Controller xử lý các API endpoints cho User management
 * Hỗ trợ CRUD operations với custom i18n messages và authorization
 */

@Auth()
@UseGuards(PoliciesGuard)
@Controller('users')
export class UserController {
  constructor(private readonly userService: UserService) {}

  // ================================================================
  // Public Methods - API Endpoints
  // ================================================================

  @Post()
  @CheckPolicies((ability: AppAbility) => ability.can(Action.Create, 'User'))
  @HttpCode(HttpStatus.CREATED)
  async create(@Body() createUserDto: CreateUserDto) {
    const result = await this.userService.create(createUserDto)
    return {
      message: result.message,
      data: UserDto.fromEntity(result.data)
    }
  }

  @Get()
  @CheckPolicies((ability: AppAbility) => ability.can(Action.Read, 'User'))
  async findAll() {
    const result = await this.userService.findAll()
    return {
      message: result.message,
      data: result.data.map((user) => UserDto.fromEntity(user))
    }
  }

  @Get(':id')
  @CheckPolicies((ability: AppAbility) => ability.can(Action.Read, 'User'))
  async findOne(@Param('id', ParseIntPipe) id: number) {
    const result = await this.userService.findOne(id)
    return {
      message: result.message,
      data: UserDto.fromEntity(result.data)
    }
  }

  @Patch(':id')
  @CheckPolicies((ability: AppAbility) => ability.can(Action.Update, 'User'))
  async update(@Param('id', ParseIntPipe) id: number, @Body() updateUserDto: UpdateUserDto) {
    const result = await this.userService.update(id, updateUserDto)
    return {
      message: result.message,
      data: UserDto.fromEntity(result.data)
    }
  }

  @Delete(':id')
  @CheckPolicies((ability: AppAbility) => ability.can(Action.Delete, 'User'))
  @HttpCode(HttpStatus.NO_CONTENT)
  async remove(@Param('id', ParseIntPipe) id: number): Promise<void> {
    await this.userService.remove(id)
    // DELETE endpoints typically return 204 No Content without response body
    // The success message will be handled by the interceptor if needed
  }
}
