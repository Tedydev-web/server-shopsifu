import {
  Controller,
  Get,
  Post,
  Body,
  Param,
  Patch,
  Query,
  HttpCode,
  HttpStatus,
  Logger,
  Ip,
  Res,
  Inject,
  forwardRef,
  Delete,
  UseGuards
} from '@nestjs/common'
import { SessionsService } from '../services/session.service'
import { ActiveUser } from 'src/shared/decorators/active-user.decorator'
import { AccessTokenPayload } from 'src/routes/auth/auth.types'
import { UserAgent } from 'src/shared/decorators/user-agent.decorator'
import {
  GetSessionsQueryDto,
  GetGroupedSessionsResponseDto,
  RevokeSessionsBodyDto,
  DeviceIdParamsDto,
  UpdateDeviceNameBodyDto,
  RevokeAllSessionsBodyDto
} from '../dtos/session.dto'
import { TypeOfVerificationCode } from 'src/routes/auth/auth.constants'
import { Response } from 'express'
import { Auth } from 'src/shared/decorators/auth.decorator'
import { AuthVerificationService } from '../services/auth-verification.service'
import { AuthError } from '../auth.error'
import { PoliciesGuard } from 'src/shared/guards/policies.guard'
import { CheckPolicies } from 'src/shared/decorators/check-policies.decorator'
import { Action, AppAbility } from 'src/shared/casl/casl-ability.factory'

interface CurrentUserContext {
  userId: number
  sessionId: string
  deviceId: number
  email?: string
}

@Auth()
@UseGuards(PoliciesGuard)
@Controller('sessions')
export class SessionsController {
  private readonly logger = new Logger(SessionsController.name)

  constructor(
    private readonly sessionsService: SessionsService,
    @Inject(forwardRef(() => AuthVerificationService))
    private readonly authVerificationService: AuthVerificationService
  ) {}

  /**
   * Lấy tất cả sessions của người dùng, nhóm theo thiết bị
   */
  @Get()
  @CheckPolicies((ability: AppAbility) => ability.can(Action.Read, 'Device'))
  async getSessions(@ActiveUser() activeUser: AccessTokenPayload, @Query() query: GetSessionsQueryDto): Promise<any> {
    if (query.page < 1 || query.limit < 1) {
      throw AuthError.InvalidPageOrLimit()
    }
    const userContext = this.getUserContext(activeUser)
    const sessions = await this.sessionsService.getSessions(
      userContext.userId,
      query.page,
      query.limit,
      userContext.sessionId
    )
    if (!sessions || sessions.devices.length === 0) {
      throw AuthError.SessionsNotFound()
    }
    return {
      message: 'auth.success.sessions.get',
      data: sessions
    }
  }

  /**
   * Thu hồi một hoặc nhiều phiên đăng nhập hoặc thiết bị
   */
  @Post('revoke')
  @CheckPolicies((ability: AppAbility) => ability.can(Action.Delete, 'Device'))
  @HttpCode(HttpStatus.OK)
  async revokeSessions(
    @ActiveUser() activeUser: AccessTokenPayload,
    @Body() body: RevokeSessionsBodyDto,
    @UserAgent() userAgent: string,
    @Ip() ip: string,
    @Res({ passthrough: true }) res: Response
  ): Promise<any> {
    const userContext = this.getUserContext(activeUser)

    if (!body.sessionIds?.length && !body.deviceIds?.length) {
      throw AuthError.InvalidRevokeParams()
    }
    if (!userContext.email) {
      throw AuthError.EmailRequired()
    }

    const revocationOptions = {
      sessionIds: body.sessionIds,
      deviceIds: body.deviceIds,
      excludeCurrentSession: body.excludeCurrentSession
    }

    const requiresVerification = await this.sessionsService.checkIfActionRequiresVerification(
      userContext.userId,
      revocationOptions
    )

    if (requiresVerification) {
      return this.authVerificationService.initiateVerification(
        {
          userId: userContext.userId,
          deviceId: userContext.deviceId,
          email: userContext.email,
          ipAddress: ip,
          userAgent,
          purpose: TypeOfVerificationCode.REVOKE_SESSIONS,
          metadata: {
            ...revocationOptions,
            currentSessionId: userContext.sessionId,
            currentDeviceId: userContext.deviceId
          }
        },
        res
      )
    }

    const result = await this.sessionsService.revokeItems(userContext.userId, revocationOptions, userContext)

    if (result.data.revokedSessionsCount === 0 && result.data.untrustedDevicesCount === 0) {
      throw AuthError.SessionOrDeviceNotFound()
    }

    return {
      message: result.message, // Service already returns an i18n key
      data: {
        revokedSessionsCount: result.data.revokedSessionsCount,
        untrustedDevicesCount: result.data.untrustedDevicesCount
      }
    }
  }

  /**
   * Thu hồi tất cả phiên đăng nhập
   */
  @Post('revoke-all')
  @CheckPolicies((ability: AppAbility) => ability.can(Action.Delete, 'Device'))
  @HttpCode(HttpStatus.OK)
  async revokeAllSessions(
    @ActiveUser() activeUser: AccessTokenPayload,
    @Body() body: RevokeAllSessionsBodyDto,
    @UserAgent() userAgent: string,
    @Ip() ip: string,
    @Res({ passthrough: true }) res: Response
  ): Promise<any> {
    const userContext = this.getUserContext(activeUser)

    if (!userContext.email) {
      throw AuthError.EmailRequired()
    }

    return this.authVerificationService.initiateVerification(
      {
        userId: userContext.userId,
        deviceId: userContext.deviceId,
        email: userContext.email,
        ipAddress: ip,
        userAgent,
        purpose: TypeOfVerificationCode.REVOKE_ALL_SESSIONS,
        metadata: {
          excludeCurrentSession: body.excludeCurrentSession,
          currentSessionId: userContext.sessionId,
          currentDeviceId: userContext.deviceId
        }
      },
      res
    )
  }

  /**
   * Tạo đối tượng UserContext từ AccessTokenPayload
   */
  private getUserContext(activeUser: AccessTokenPayload): CurrentUserContext {
    return {
      userId: activeUser.userId,
      sessionId: activeUser.sessionId,
      deviceId: activeUser.deviceId,
      email: activeUser.email
    }
  }

  /**
   * Cập nhật tên thiết bị
   */
  @Patch('devices/:deviceId/name')
  @CheckPolicies((ability: AppAbility) => ability.can(Action.Update, 'Device'))
  @HttpCode(HttpStatus.OK)
  async updateDeviceName(
    @ActiveUser() activeUser: AccessTokenPayload,
    @Param() params: DeviceIdParamsDto,
    @Body() body: UpdateDeviceNameBodyDto
  ): Promise<any> {
    if (isNaN(params.deviceId)) throw AuthError.InvalidDeviceId()
    if (!body.name || body.name.trim().length === 0) throw AuthError.InvalidDeviceName()

    await this.sessionsService.updateDeviceName(activeUser.userId, params.deviceId, body.name)

    return {
      message: 'auth.success.device.nameUpdated',
      data: {
        deviceId: params.deviceId,
        name: body.name
      }
    }
  }

  /**
   * Đánh dấu thiết bị hiện tại là đáng tin cậy
   */
  @Post('devices/trust-current')
  @CheckPolicies((ability: AppAbility) => ability.can(Action.Update, 'Device'))
  @HttpCode(HttpStatus.OK)
  async trustCurrentDevice(@ActiveUser() activeUser: AccessTokenPayload): Promise<any> {
    this.logger.debug(`[trustCurrentDevice] User ${activeUser.userId} trusting device ${activeUser.deviceId}`)
    await this.sessionsService.trustCurrentDevice(activeUser.userId, activeUser.deviceId)

    return {
      message: 'auth.success.device.trusted'
    }
  }

  /**
   * Hủy bỏ trạng thái đáng tin cậy của thiết bị
   */
  @Delete('devices/:deviceId/untrust')
  @CheckPolicies((ability: AppAbility) => ability.can(Action.Update, 'Device'))
  @HttpCode(HttpStatus.OK)
  async untrustDevice(@ActiveUser() activeUser: AccessTokenPayload, @Param() params: DeviceIdParamsDto): Promise<any> {
    if (isNaN(params.deviceId)) throw AuthError.InvalidDeviceId()

    this.logger.debug(`[untrustDevice] User ${activeUser.userId} untrusting device ${params.deviceId}`)
    await this.sessionsService.untrustDevice(activeUser.userId, params.deviceId)

    return {
      message: 'auth.success.device.untrusted',
      data: { deviceId: params.deviceId }
    }
  }
}
