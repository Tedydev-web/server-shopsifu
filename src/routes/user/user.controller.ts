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
  UseGuards,
  Ip,
  Res
} from '@nestjs/common'
import { Response } from 'express'

// ================================================================
// Internal Services & Types
// ================================================================
import { UserService } from './user.service'
import { CreateUserDto, UpdateUserDto, UserDto } from './user.dto'

// ================================================================
// Decorators & Guards
// ================================================================
import { Auth } from 'src/shared/decorators/auth.decorator'
import { PermissionGuard } from 'src/shared/guards/permission.guard'
import { RequirePermissions } from 'src/shared/decorators/permissions.decorator'
import { UserAgent } from 'src/shared/decorators/user-agent.decorator'
import { Action, AppSubject } from 'src/shared/providers/casl/casl-ability.factory'
import { User } from './user.model'

@Auth()
@UseGuards(PermissionGuard)
@Controller('users')
export class UserController {
  constructor(private readonly userService: UserService) {}

  @Post()
  @HttpCode(HttpStatus.CREATED)
  @RequirePermissions({ action: Action.Create, subject: AppSubject.User })
  async create(
    @Body() createUserDto: CreateUserDto,
    @Ip() ip: string,
    @UserAgent() userAgent: string,
    @Res({ passthrough: true }) res: Response
  ) {
    return await this.userService.initiateUserCreation(createUserDto, ip, userAgent, res)
  }

  // ================================================================
  // Standard CRUD Operations
  // ================================================================

  @Get()
  @RequirePermissions({ action: Action.Read, subject: AppSubject.User })
  async findAll() {
    const result = await this.userService.findAll()
    return {
      message: result.message,
      data: result.data.map((user) => UserDto.fromEntity(user))
    }
  }

  @Get(':id')
  @RequirePermissions({ action: Action.Read, subject: User })
  async findOne(@Param('id', ParseIntPipe) id: number) {
    const { message, data } = await this.userService.findOne(id)
    return {
      message,
      data: UserDto.fromEntity(data)
    }
  }

  @Patch(':id')
  @RequirePermissions({ action: Action.Update, subject: User })
  async update(@Param('id', ParseIntPipe) id: number, @Body() updateUserDto: UpdateUserDto) {
    const { message, data } = await this.userService.update(id, updateUserDto)
    return {
      message,
      data: UserDto.fromEntity(data)
    }
  }

  @Delete(':id')
  @HttpCode(HttpStatus.NO_CONTENT)
  @RequirePermissions({ action: Action.Delete, subject: User })
  async remove(@Param('id', ParseIntPipe) id: number): Promise<void> {
    await this.userService.remove(id)
  }
}
