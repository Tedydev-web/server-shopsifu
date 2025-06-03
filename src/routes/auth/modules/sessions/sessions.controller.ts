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
  RevokeSessionsBodyDto,
  RevokeSessionsResponseDto,
  DeviceIdParamsDto,
  UpdateDeviceNameBodyDto,
  UpdateDeviceNameResponseDto,
  TrustDeviceResponseDto,
  UntrustDeviceResponseDto
} from './dto/session.dto'
import { I18nService } from 'nestjs-i18n'
import { DynamicZodSerializer } from 'src/shared/interceptor/dynamic-zod-serializer.interceptor'

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
  @DynamicZodSerializer({
    schema: GetGroupedSessionsResponseDto.schema,
    predicate: () => true
  })
  async getSessions(
    @ActiveUser() activeUser: AccessTokenPayload,
    @Query() query: GetSessionsQueryDto
  ): Promise<GetGroupedSessionsResponseDto> {
    this.logger.debug(
      `[SessionsController.getSessions] User ${activeUser.userId} requesting sessions. Page: ${query.page}, Limit: ${query.limit}`
    )
    return await this.sessionsService.getSessions(activeUser.userId, query.page, query.limit, activeUser.sessionId)
  }

  /**
   * Thu hồi sessions và devices
   * Một endpoint duy nhất để xử lý tất cả các trường hợp thu hồi:
   * 1. Thu hồi một hoặc nhiều sessions cụ thể
   * 2. Thu hồi một hoặc nhiều devices (và tất cả sessions liên quan)
   * 3. Thu hồi tất cả sessions (trừ session hiện tại nếu cần)
   */
  @Post('revoke')
  @HttpCode(HttpStatus.OK)
  async revokeSessions(
    @ActiveUser() activeUser: AccessTokenPayload,
    @Body() body: RevokeSessionsBodyDto,
    @UserAgent() userAgent: string,
    @Ip() ip: string
  ): Promise<{
    statusCode: number
    message: string
    data: RevokeSessionsResponseDto
  }> {
    this.logger.debug(
      `[SessionsController.revokeSessions] User ${activeUser.userId} revoking sessions/devices with: ${JSON.stringify(body)}`
    )

    // Single session revocation (backward compatibility)
    if (body.sessionIds?.length === 1 && !body.deviceIds?.length && !body.revokeAll) {
      const sessionId = body.sessionIds[0]
      const result = await this.sessionsService.revokeSession(
        activeUser.userId,
        sessionId,
        body.excludeCurrentSession ? activeUser.sessionId : undefined
      )

      return {
        statusCode: HttpStatus.OK,
        message: result.message,
        data: {
          revokedSessionsCount: 1,
          untrustedDevicesCount: 0,
          revokedSessionIds: [sessionId],
          revokedDeviceIds: [],
          requiresAdditionalVerification: false,
          verificationRedirectUrl: undefined
        }
      }
    }

    // Nhiều sessions/devices hoặc tất cả
    const options = {
      sessionIds: body.sessionIds,
      deviceIds: body.deviceIds,
      revokeAllUserSessions: body.revokeAll,
      excludeCurrentSession: body.excludeCurrentSession
    }

    const result = await this.sessionsService.revokeItems(activeUser.userId, options, activeUser)

    return {
      statusCode: HttpStatus.OK,
      message: result.message,
      data: {
        revokedSessionsCount: result.revokedSessionsCount,
        untrustedDevicesCount: result.untrustedDevicesCount,
        revokedSessionIds: result.revokedSessionIds || [],
        revokedDeviceIds: result.revokedDeviceIds || [],
        requiresAdditionalVerification: result.requiresAdditionalVerification || false,
        verificationRedirectUrl: result.verificationRedirectUrl
      }
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
