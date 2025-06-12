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
import { RequirePermissions, PermissionCondition } from 'src/shared/decorators/permissions.decorator'
import { UserAgent } from 'src/shared/decorators/user-agent.decorator'

/**
 * Controller xử lý các API endpoints cho User management
 * Sử dụng flow OTP verification thống nhất cho tạo user và CRUD operations
 */

@Auth()
@UseGuards(PermissionGuard)
@Controller('users')
export class UserController {
  constructor(private readonly userService: UserService) {}

  // ================================================================
  // User Creation with OTP Verification Flow
  // ================================================================

  /**
   * Tạo user mới với OTP verification
   * Flow: Submit data → SLT token + OTP → Verify qua auth/otp/verify → User được tạo
   */
  @Post()
  @RequirePermissions(['User:create'])
  @HttpCode(HttpStatus.OK)
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
  @RequirePermissions(['User:read'])
  async findAll() {
    const result = await this.userService.findAll()
    return {
      message: result.message,
      data: result.data.map((user) => UserDto.fromEntity(user))
    }
  }

  @Get(':id')
  @RequirePermissions(['User:read'])
  async findOne(@Param('id', ParseIntPipe) id: number) {
    const result = await this.userService.findOne(id)
    return {
      message: result.message,
      data: UserDto.fromEntity(result.data)
    }
  }

  @Patch(':id')
  @RequirePermissions(['User:update', 'User:update:own'], { condition: PermissionCondition.OR })
  async update(@Param('id', ParseIntPipe) id: number, @Body() updateUserDto: UpdateUserDto) {
    const result = await this.userService.update(id, updateUserDto)
    return {
      message: result.message,
      data: UserDto.fromEntity(result.data)
    }
  }

  @Delete(':id')
  @RequirePermissions(['User:delete'])
  @HttpCode(HttpStatus.NO_CONTENT)
  async remove(@Param('id', ParseIntPipe) id: number): Promise<void> {
    await this.userService.remove(id)
    // DELETE endpoints typically return 204 No Content without response body
    // The success message will be handled by the interceptor if needed
  }
}
