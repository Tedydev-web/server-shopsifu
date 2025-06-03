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
  HttpCode,
  HttpStatus,
  Logger
} from '@nestjs/common'
import { SessionsService } from './sessions.service'
import { AccessTokenGuard } from 'src/routes/auth/guards/access-token.guard'
import { ActiveUser } from 'src/routes/auth/decorators/active-user.decorator'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'
import { UserAgent } from 'src/shared/decorators/user-agent.decorator'
import { Ip } from '@nestjs/common'
import {
  GetSessionsQueryDto,
  GetGroupedSessionsResponseDto,
  RevokeSessionParamsDto,
  RevokeItemsBodyDto,
  RevokeItemsResponseDto,
  DeviceIdParamsDto,
  UpdateDeviceNameBodyDto,
  UpdateDeviceNameResponseDto,
  TrustDeviceResponseDto,
  UntrustDeviceResponseDto
} from './dto/session.dto'

@UseGuards(AccessTokenGuard)
@Controller('auth/sessions')
export class SessionsController {
  private readonly logger = new Logger(SessionsController.name)

  constructor(private readonly sessionsService: SessionsService) {}

  @Get()
  @HttpCode(HttpStatus.OK)
  async getSessions(
    @ActiveUser() activeUser: AccessTokenPayload,
    @Query() query: GetSessionsQueryDto
  ): Promise<GetGroupedSessionsResponseDto> {
    this.logger.debug(
      `[SessionsController.getSessions] User ${activeUser.userId} requesting sessions. Page: ${query.page}, Limit: ${query.limit}`
    )
    return this.sessionsService.getSessions(activeUser.userId, query.page, query.limit, activeUser.sessionId)
  }

  @Delete(':sessionId')
  @HttpCode(HttpStatus.NO_CONTENT)
  async revokeSingleSession(
    @ActiveUser() activeUser: AccessTokenPayload,
    @Param() params: RevokeSessionParamsDto
  ): Promise<void> {
    this.logger.debug(
      `[SessionsController.revokeSingleSession] User ${activeUser.userId} revoking session ${params.sessionId}`
    )
    await this.sessionsService.revokeSession(activeUser.userId, params.sessionId, activeUser.sessionId)
  }

  @Post('revoke-items')
  @HttpCode(HttpStatus.OK)
  async revokeMultipleItems(
    @ActiveUser() activeUser: AccessTokenPayload,
    @Body() body: RevokeItemsBodyDto
  ): Promise<RevokeItemsResponseDto> {
    this.logger.debug(
      `[SessionsController.revokeMultipleItems] User ${activeUser.userId} revoking items with body: ${JSON.stringify(body)}`
    )
    return this.sessionsService.revokeItems(activeUser.userId, body, activeUser)
  }

  @Patch('devices/:deviceId/name')
  @HttpCode(HttpStatus.OK)
  async updateDeviceName(
    @ActiveUser() activeUser: AccessTokenPayload,
    @Param() params: DeviceIdParamsDto,
    @Body() body: UpdateDeviceNameBodyDto
  ): Promise<UpdateDeviceNameResponseDto> {
    this.logger.debug(
      `[SessionsController.updateDeviceName] User ${activeUser.userId} updating device ${params.deviceId} name to "${body.name}"`
    )
    return this.sessionsService.updateDeviceName(activeUser.userId, params.deviceId, body.name)
  }

  @Post('devices/:deviceId/trust')
  @HttpCode(HttpStatus.OK)
  async trustDevice(
    @ActiveUser() activeUser: AccessTokenPayload,
    @Param() params: DeviceIdParamsDto,
    @Ip() ip: string,
    @UserAgent() userAgent: string
  ): Promise<TrustDeviceResponseDto> {
    this.logger.debug(`[SessionsController.trustDevice] User ${activeUser.userId} trusting device ${params.deviceId}`)
    return this.sessionsService.trustDevice(activeUser.userId, params.deviceId, ip, userAgent)
  }

  @Post('devices/:deviceId/untrust')
  @HttpCode(HttpStatus.OK)
  async untrustDevice(
    @ActiveUser() activeUser: AccessTokenPayload,
    @Param() params: DeviceIdParamsDto
  ): Promise<UntrustDeviceResponseDto> {
    this.logger.debug(
      `[SessionsController.untrustDevice] User ${activeUser.userId} untrusting device ${params.deviceId}`
    )
    return this.sessionsService.untrustDevice(activeUser.userId, params.deviceId)
  }

  @Post('current-device/trust')
  @HttpCode(HttpStatus.OK)
  async trustCurrentDevice(
    @ActiveUser() activeUser: AccessTokenPayload,
    @Ip() ip: string,
    @UserAgent() userAgent: string
  ): Promise<TrustDeviceResponseDto> {
    this.logger.debug(
      `[SessionsController.trustCurrentDevice] User ${activeUser.userId} trusting current device ${activeUser.deviceId}`
    )
    return this.sessionsService.trustCurrentDevice(activeUser.userId, activeUser.deviceId, ip, userAgent)
  }
}
