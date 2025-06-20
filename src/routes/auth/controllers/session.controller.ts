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
  Delete
} from '@nestjs/common'
import { SessionsService } from '../services/session.service'
import { ActiveUser } from 'src/shared/decorators/active-user.decorator'
import { ActiveUserData } from 'src/shared/types/active-user.type'
import { UserAgent } from 'src/shared/decorators/user-agent.decorator'
import {
  GetSessionsQueryDto,
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
import { CurrentUserContext } from 'src/shared/types/current-user-context.type'
import { AppSubject } from 'src/shared/providers/casl/casl-ability.factory'
import { Action } from 'src/shared/providers/casl/casl-ability.factory'
import { RequirePermissions } from 'src/shared/decorators/permissions.decorator'

@Auth()
@Controller('sessions')
export class SessionsController {
  private readonly logger = new Logger(SessionsController.name)

  constructor(
    private readonly sessionsService: SessionsService,
    @Inject(forwardRef(() => AuthVerificationService))
    private readonly authVerificationService: AuthVerificationService
  ) {}

  @Get()
  @RequirePermissions({ action: Action.Read, subject: AppSubject.Session })
  async getSessions(@ActiveUser() activeUser: ActiveUserData, @Query() query: GetSessionsQueryDto): Promise<any> {
    const userContext = this.getUserContext(activeUser)
    const sessions = await this.sessionsService.getSessions(userContext.userId, query, userContext.sessionId)
    // Tạo response với thứ tự đúng: status, message, data, metadata
    const orderedResponse: any = {}
    orderedResponse.status = 200
    orderedResponse.message = 'auth.success.sessions.get'
    orderedResponse.data = sessions.data
    orderedResponse.metadata = sessions.metadata
    return orderedResponse
  }

  @Post('revoke')
  @RequirePermissions({ action: Action.Delete, subject: AppSubject.Session })
  @HttpCode(HttpStatus.OK)
  async revokeSessions(
    @ActiveUser() activeUser: ActiveUserData,
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

    try {
      const result = await this.sessionsService.revokeItems(
        userContext.userId,
        revocationOptions,
        {
          sessionId: userContext.sessionId,
          deviceId: userContext.deviceId
        },
        res
      )

      // Always return success response - no need to throw errors for revocation
      return {
        message: result.message,
        success: result.data.revokedSessionsCount > 0 || result.data.untrustedDevicesCount > 0,
        revokedCount: result.data.revokedSessionsCount,
        untrustedDevicesCount: result.data.untrustedDevicesCount
      }
    } catch (error) {
      // If action requires confirmation, initiate verification
      if (error.code === 'AUTH_ACTION_REQUIRES_CONFIRMATION') {
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
      throw error
    }
  }

  @Post('revoke-all')
  @RequirePermissions({ action: Action.Delete, subject: AppSubject.Session })
  @HttpCode(HttpStatus.OK)
  async revokeAllSessions(
    @ActiveUser() activeUser: ActiveUserData,
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
          untrustAllDevices: body.untrustAllDevices ?? true, // Default to true for security
          currentSessionId: userContext.sessionId,
          currentDeviceId: userContext.deviceId
        }
      },
      res
    )
  }

  private getUserContext(activeUser: ActiveUserData): CurrentUserContext {
    return {
      userId: activeUser.id,
      sessionId: activeUser.sessionId,
      deviceId: activeUser.deviceId,
      email: activeUser.email
    }
  }

  @Patch('devices/:deviceId/name')
  @RequirePermissions({ action: Action.Update, subject: AppSubject.Session })
  @HttpCode(HttpStatus.OK)
  async updateDeviceName(
    @ActiveUser() activeUser: ActiveUserData,
    @Param() params: DeviceIdParamsDto,
    @Body() body: UpdateDeviceNameBodyDto
  ): Promise<any> {
    if (isNaN(params.deviceId)) throw AuthError.InvalidDeviceId()
    if (!body.name || body.name.trim().length === 0) throw AuthError.InvalidDeviceName()

    await this.sessionsService.updateDeviceName(activeUser.id, params.deviceId, body.name)

    return {
      message: 'auth.success.device.nameUpdated',
      deviceId: params.deviceId,
      name: body.name
    }
  }

  @Post('devices/trust-current')
  @RequirePermissions({ action: Action.Update, subject: AppSubject.Session })
  @HttpCode(HttpStatus.OK)
  async trustCurrentDevice(@ActiveUser() activeUser: ActiveUserData): Promise<any> {
    if (!activeUser.id || !activeUser.deviceId) {
      throw AuthError.Unauthorized()
    }
    await this.sessionsService.trustCurrentDevice(activeUser.id, activeUser.deviceId)

    return {
      message: 'auth.success.device.trusted'
    }
  }

  @Delete('devices/:deviceId/untrust')
  @RequirePermissions({ action: Action.Delete, subject: AppSubject.Session })
  @HttpCode(HttpStatus.OK)
  async untrustDevice(@ActiveUser() activeUser: ActiveUserData, @Param() params: DeviceIdParamsDto): Promise<any> {
    if (isNaN(params.deviceId)) throw AuthError.InvalidDeviceId()

    await this.sessionsService.untrustDevice(activeUser.id, params.deviceId)

    return {
      message: 'auth.success.device.untrusted',
      deviceId: params.deviceId
    }
  }
}
