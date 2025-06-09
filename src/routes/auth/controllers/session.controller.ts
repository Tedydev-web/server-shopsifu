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
  forwardRef
} from '@nestjs/common'
import { SessionsService } from '../services/session.service'
import { ActiveUser } from 'src/shared/decorators/active-user.decorator'
import { AccessTokenPayload } from 'src/shared/types/auth.types'
import { UserAgent } from 'src/shared/decorators/user-agent.decorator'
import {
  GetSessionsQueryDto,
  GetGroupedSessionsResponseDto,
  RevokeSessionsBodyDto,
  DeviceIdParamsDto,
  UpdateDeviceNameBodyDto,
  RevokeAllSessionsBodyDto
} from '../dtos/session.dto'
import { I18nService } from 'nestjs-i18n'
import { TypeOfVerificationCode } from 'src/routes/auth/auth.constants'
import { Response } from 'express'
import { AuthError } from '../auth.error'
import { Auth } from 'src/shared/decorators/auth.decorator'
import { AuthVerificationService } from '../services/auth-verification.service'
import { SuccessMessage } from 'src/shared/decorators/success-message.decorator'

interface CurrentUserContext {
  userId: number
  sessionId: string
  deviceId: number
  email?: string
}

@Auth()
@Controller('auth/sessions')
export class SessionsController {
  private readonly logger = new Logger(SessionsController.name)

  constructor(
    private readonly sessionsService: SessionsService,
    private readonly i18nService: I18nService,
    @Inject(forwardRef(() => AuthVerificationService))
    private readonly authVerificationService: AuthVerificationService
  ) {}

  /**
   * Lấy tất cả sessions của người dùng, nhóm theo thiết bị
   */
  @Get()
  @HttpCode(HttpStatus.OK)
  @SuccessMessage('auth.Auth.Session.FetchSuccess')
  async getSessions(
    @ActiveUser() activeUser: AccessTokenPayload,
    @Query() query: GetSessionsQueryDto
  ): Promise<GetGroupedSessionsResponseDto> {
    return this.sessionsService.getSessions(activeUser.userId, query.page, query.limit, activeUser.sessionId)
  }

  /**
   * Thu hồi một hoặc nhiều phiên đăng nhập hoặc thiết bị
   */
  @Post('revoke')
  @HttpCode(HttpStatus.OK)
  async revokeSessions(
    @ActiveUser() activeUser: AccessTokenPayload,
    @Body() body: RevokeSessionsBodyDto,
    @UserAgent() userAgent: string,
    @Ip() ip: string,
    @Res({ passthrough: true }) res: Response
  ): Promise<any> {
    const userContext = this.getUserContext(activeUser)
    const { sessionIds, deviceIds, excludeCurrentSession } = body

    const revocationOptions = { sessionIds, deviceIds, excludeCurrentSession }
    const requiresVerification = await this.sessionsService.checkIfActionRequiresVerification(
      userContext.userId,
      revocationOptions
    )

    if (requiresVerification) {
      if (!userContext.email) {
        throw AuthError.InternalServerError('Active user email missing in token.')
      }

      const verificationResult = await this.authVerificationService.initiateVerification(
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
      return {
        message: verificationResult.message,
        ...verificationResult
      }
    }

    const result = await this.sessionsService.revokeItems(userContext.userId, revocationOptions, userContext)
    return {
      message: result.message,
      revokedSessionsCount: result.revokedSessionsCount,
      untrustedDevicesCount: result.untrustedDevicesCount
    }
  }

  /**
   * Thu hồi tất cả phiên đăng nhập
   */
  @Post('revoke-all')
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
      throw AuthError.InternalServerError('Active user email missing in token.')
    }

    const verificationResult = await this.authVerificationService.initiateVerification(
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

    return {
      message: verificationResult.message,
      verificationType: verificationResult.verificationType
    }
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
  @HttpCode(HttpStatus.OK)
  async updateDeviceName(
    @ActiveUser() activeUser: AccessTokenPayload,
    @Param() params: DeviceIdParamsDto,
    @Body() body: UpdateDeviceNameBodyDto
  ): Promise<{ message: string; deviceId: number; name: string }> {
    await this.sessionsService.updateDeviceName(activeUser.userId, params.deviceId, body.name)
    return {
      message: 'auth.Auth.Device.NameUpdated',
      deviceId: params.deviceId,
      name: body.name
    }
  }

  /**
   * Đánh dấu thiết bị hiện tại là đáng tin cậy
   */
  @Patch('current-device/trust')
  @HttpCode(HttpStatus.OK)
  async trustCurrentDevice(@ActiveUser() activeUser: AccessTokenPayload): Promise<{ message: string }> {
    this.logger.debug(`[trustCurrentDevice] User ${activeUser.userId} trusting device ${activeUser.deviceId}`)
    await this.sessionsService.trustCurrentDevice(activeUser.userId, activeUser.deviceId)
    return {
      message: 'auth.Auth.Device.Trusted'
    }
  }

  /**
   * Hủy bỏ trạng thái đáng tin cậy của thiết bị
   */
  @Patch('devices/:deviceId/untrust')
  @HttpCode(HttpStatus.OK)
  async untrustDevice(
    @ActiveUser() activeUser: AccessTokenPayload,
    @Param() params: DeviceIdParamsDto
  ): Promise<{ message: string; deviceId: number }> {
    this.logger.debug(`[untrustDevice] User ${activeUser.userId} untrusting device ${params.deviceId}`)
    await this.sessionsService.untrustDevice(activeUser.userId, params.deviceId)
    return {
      message: 'auth.Auth.Device.Untrusted',
      deviceId: params.deviceId
    }
  }
}
