import {
  Controller,
  Get,
  Post,
  Body,
  Param,
  Patch,
  Delete,
  Query,
  UseGuards,
  Req,
  HttpCode,
  HttpStatus,
  Logger,
  Ip
} from '@nestjs/common'
import { ZodSerializerDto } from 'nestjs-zod'
import { SessionsService } from './sessions.service'
import { AccessTokenGuard } from 'src/routes/auth/guards/access-token.guard'
import { ActiveUser } from 'src/routes/auth/decorators/active-user.decorator'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'
import { Request } from 'express'
import { UserAgent } from 'src/shared/decorators/user-agent.decorator'
import {
  DeviceIdParamsDto,
  GetSessionsQueryDto,
  GetSessionsResponseDto,
  RevokeSessionParamsDto,
  RevokeSessionResponseDto,
  RevokeSessionsBodyDto,
  RevokeSessionsResponseDto,
  TrustDeviceBodyDto,
  TrustDeviceResponseDto,
  UntrustDeviceBodyDto,
  UntrustDeviceResponseDto,
  UpdateDeviceNameBodyDto,
  UpdateDeviceNameResponseDto
} from './dto/session.dto'

@UseGuards(AccessTokenGuard)
@Controller('auth/sessions')
export class SessionsController {
  private readonly logger = new Logger(SessionsController.name)

  constructor(private readonly sessionsService: SessionsService) {}

  /**
   * Lấy danh sách sessions của user
   */
  @Get()
  @HttpCode(HttpStatus.OK)
  @ZodSerializerDto(GetSessionsResponseDto)
  async getSessions(@ActiveUser() activeUser: AccessTokenPayload, @Query() query: GetSessionsQueryDto) {
    const result = await this.sessionsService.getSessions(activeUser.userId, query.page, query.limit)

    // Chuyển đổi kết quả để phù hợp với GetSessionsResponseDto
    return {
      data: result.data,
      meta: {
        page: result.page,
        limit: result.limit,
        total: result.total,
        totalPages: result.totalPages
      }
    }
  }

  /**
   * Thu hồi một session
   */
  @Delete(':sessionId')
  @HttpCode(HttpStatus.NO_CONTENT)
  async revokeSession(@ActiveUser() activeUser: AccessTokenPayload, @Param('sessionId') sessionId: string) {
    await this.sessionsService.revokeSession(activeUser.userId, sessionId, activeUser.sessionId)
  }

  /**
   * Thu hồi nhiều session
   */
  @Post('revoke-multiple')
  @HttpCode(HttpStatus.OK)
  @ZodSerializerDto(RevokeSessionsResponseDto)
  async revokeSessions(
    @ActiveUser() activeUser: AccessTokenPayload,
    @Body() body: RevokeSessionsBodyDto
  ): Promise<RevokeSessionsResponseDto> {
    return this.sessionsService.revokeSessions(
      activeUser.userId,
      {
        sessionIds: body.sessionIds,
        revokeAll: body.revokeAll,
        excludeCurrentSession: body.excludeCurrentSession
      },
      activeUser.sessionId
    )
  }

  /**
   * Cập nhật tên thiết bị
   */
  @Patch('devices/:deviceId/name')
  @HttpCode(HttpStatus.OK)
  @ZodSerializerDto(UpdateDeviceNameResponseDto)
  async updateDeviceName(
    @ActiveUser() activeUser: AccessTokenPayload,
    @Param() params: DeviceIdParamsDto,
    @Body() body: UpdateDeviceNameBodyDto
  ): Promise<UpdateDeviceNameResponseDto> {
    return this.sessionsService.updateDeviceName(activeUser.userId, params.deviceId, body.name)
  }

  /**
   * Đánh dấu thiết bị là đáng tin cậy
   */
  @Post('devices/:deviceId/trust')
  @HttpCode(HttpStatus.OK)
  @ZodSerializerDto(TrustDeviceResponseDto)
  async trustDevice(
    @ActiveUser() activeUser: AccessTokenPayload,
    @Param() params: DeviceIdParamsDto,
    @Body() _: TrustDeviceBodyDto,
    @Ip() ip: string,
    @UserAgent() userAgent: string
  ): Promise<TrustDeviceResponseDto> {
    return this.sessionsService.trustDevice(activeUser.userId, params.deviceId, ip, userAgent)
  }

  /**
   * Bỏ đánh dấu thiết bị là đáng tin cậy
   */
  @Post('devices/:deviceId/untrust')
  @HttpCode(HttpStatus.OK)
  @ZodSerializerDto(UntrustDeviceResponseDto)
  async untrustDevice(
    @ActiveUser() activeUser: AccessTokenPayload,
    @Param() params: DeviceIdParamsDto,
    @Body() _: UntrustDeviceBodyDto
  ): Promise<UntrustDeviceResponseDto> {
    return this.sessionsService.untrustDevice(activeUser.userId, params.deviceId, activeUser)
  }

  /**
   * Đánh dấu thiết bị hiện tại là đáng tin cậy
   */
  @Post('current-device/trust')
  @HttpCode(HttpStatus.OK)
  @ZodSerializerDto(TrustDeviceResponseDto)
  async trustCurrentDevice(
    @ActiveUser() activeUser: AccessTokenPayload,
    @Body() _: TrustDeviceBodyDto,
    @Ip() ip: string,
    @UserAgent() userAgent: string
  ): Promise<TrustDeviceResponseDto> {
    return this.sessionsService.trustCurrentDevice(activeUser.userId, activeUser.deviceId, ip, userAgent)
  }

  /**
   * Đóng tất cả phiên trừ phiên hiện tại
   */
  @Delete()
  @HttpCode(HttpStatus.NO_CONTENT)
  async revokeAllSessions(@ActiveUser() activeUser: AccessTokenPayload) {
    await this.sessionsService.revokeSessions(activeUser.userId, { excludeCurrentSession: true }, activeUser.sessionId)
  }
}
