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
import { ZodSerializerDto } from 'nestjs-zod'
import { I18nService } from 'nestjs-i18n'

@UseGuards(AccessTokenGuard)
@Controller('auth/sessions')
export class SessionsController {
  private readonly logger = new Logger(SessionsController.name)

  constructor(
    private readonly sessionsService: SessionsService,
    private readonly i18nService: I18nService
  ) {}

  @Get()
  @HttpCode(HttpStatus.OK)
  @ZodSerializerDto(GetGroupedSessionsResponseDto)
  async getSessions(
    @ActiveUser() activeUser: AccessTokenPayload,
    @Query() query: GetSessionsQueryDto
  ): Promise<{
    statusCode: number
    message: string
    data: GetGroupedSessionsResponseDto
  }> {
    this.logger.debug(
      `[SessionsController.getSessions] User ${activeUser.userId} requesting sessions. Page: ${query.page}, Limit: ${query.limit}`
    )
    const sessionsData = await this.sessionsService.getSessions(
      activeUser.userId,
      query.page,
      query.limit,
      activeUser.sessionId
    )

    return {
      statusCode: HttpStatus.OK,
      message: 'Global.Success',
      data: sessionsData
    }
  }

  @Delete(':sessionId')
  @HttpCode(HttpStatus.OK)
  async revokeSingleSession(
    @ActiveUser() activeUser: AccessTokenPayload,
    @Param() params: RevokeSessionParamsDto
  ): Promise<{
    statusCode: number
    message: string
  }> {
    this.logger.debug(
      `[SessionsController.revokeSingleSession] User ${activeUser.userId} revoking session ${params.sessionId}`
    )
    const result = await this.sessionsService.revokeSession(activeUser.userId, params.sessionId, activeUser.sessionId)

    return {
      statusCode: HttpStatus.OK,
      message: result.message
    }
  }

  @Post('revoke-items')
  @HttpCode(HttpStatus.OK)
  async revokeMultipleItems(
    @ActiveUser() activeUser: AccessTokenPayload,
    @Body() body: RevokeItemsBodyDto
  ): Promise<{
    statusCode: number
    message: string
    data: RevokeItemsResponseDto
  }> {
    this.logger.debug(
      `[SessionsController.revokeMultipleItems] User ${activeUser.userId} revoking items with body: ${JSON.stringify(body)}`
    )
    const result = await this.sessionsService.revokeItems(activeUser.userId, body, activeUser)

    return {
      statusCode: HttpStatus.OK,
      message: result.message,
      data: result
    }
  }

  @Patch('devices/:deviceId/name')
  @HttpCode(HttpStatus.OK)
  async updateDeviceName(
    @ActiveUser() activeUser: AccessTokenPayload,
    @Param() params: DeviceIdParamsDto,
    @Body() body: UpdateDeviceNameBodyDto
  ): Promise<{
    statusCode: number
    message: string
    data: UpdateDeviceNameResponseDto
  }> {
    this.logger.debug(
      `[SessionsController.updateDeviceName] User ${activeUser.userId} updating device ${params.deviceId} name to "${body.name}"`
    )
    const result = await this.sessionsService.updateDeviceName(activeUser.userId, params.deviceId, body.name)

    return {
      statusCode: HttpStatus.OK,
      message: result.message,
      data: result
    }
  }

  @Post('devices/:deviceId/trust')
  @HttpCode(HttpStatus.OK)
  async trustDevice(
    @ActiveUser() activeUser: AccessTokenPayload,
    @Param() params: DeviceIdParamsDto,
    @Ip() ip: string,
    @UserAgent() userAgent: string
  ): Promise<{
    statusCode: number
    message: string
    data: TrustDeviceResponseDto
  }> {
    this.logger.debug(`[SessionsController.trustDevice] User ${activeUser.userId} trusting device ${params.deviceId}`)
    const result = await this.sessionsService.trustDevice(activeUser.userId, params.deviceId, ip, userAgent)

    return {
      statusCode: HttpStatus.OK,
      message: result.message,
      data: result
    }
  }

  @Post('devices/:deviceId/untrust')
  @HttpCode(HttpStatus.OK)
  async untrustDevice(
    @ActiveUser() activeUser: AccessTokenPayload,
    @Param() params: DeviceIdParamsDto
  ): Promise<{
    statusCode: number
    message: string
    data: UntrustDeviceResponseDto
  }> {
    this.logger.debug(
      `[SessionsController.untrustDevice] User ${activeUser.userId} untrusting device ${params.deviceId}`
    )
    const result = await this.sessionsService.untrustDevice(activeUser.userId, params.deviceId)

    return {
      statusCode: HttpStatus.OK,
      message: result.message,
      data: result
    }
  }

  @Post('current-device/trust')
  @HttpCode(HttpStatus.OK)
  async trustCurrentDevice(
    @ActiveUser() activeUser: AccessTokenPayload,
    @Ip() ip: string,
    @UserAgent() userAgent: string
  ): Promise<{
    statusCode: number
    message: string
    data: TrustDeviceResponseDto
  }> {
    this.logger.debug(
      `[SessionsController.trustCurrentDevice] User ${activeUser.userId} trusting current device ${activeUser.deviceId}`
    )
    const result = await this.sessionsService.trustCurrentDevice(activeUser.userId, activeUser.deviceId, ip, userAgent)

    return {
      statusCode: HttpStatus.OK,
      message: result.message,
      data: result
    }
  }
}
