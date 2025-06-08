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
  Req,
  forwardRef
} from '@nestjs/common'
import { SessionsService } from './session.service'
import { ActiveUser } from 'src/shared/decorators/active-user.decorator'
import { AccessTokenPayload } from 'src/shared/types/auth.types'
import { UserAgent } from 'src/shared/decorators/user-agent.decorator'
import {
  GetSessionsQueryDto,
  GetGroupedSessionsResponseDto,
  RevokeSessionsBodyDto,
  DeviceIdParamsDto,
  UpdateDeviceNameBodyDto,
  RevokeAllSessionsBodyDto,
  UpdateDeviceNameResponseDto,
  RevokeSessionsResponseDto,
  VerificationNeededResponseDto
} from './session.dto'
import { I18nService } from 'nestjs-i18n'
import { TypeOfVerificationCode } from 'src/shared/constants/auth/auth.constants'
import { Response, Request } from 'express'
import { AuthError } from '../../auth.error'
import { Auth } from 'src/shared/decorators/auth.decorator'
import { AuthVerificationService } from '../../../../shared/services/auth-verification.service'
import { SuccessMessage } from 'src/shared/decorators/success-message.decorator'

/**
 * Metadata cho quá trình thu hồi phiên
 */
interface RevokeMetadata {
  sessionIds?: string[]
  deviceIds?: number[]
  revokeAllUserSessions?: boolean
  excludeCurrentSession?: boolean
  currentSessionIdToExclude?: string
  currentDeviceIdToExclude?: number
  actionType: 'SINGLE' | 'MULTIPLE' | 'ALL'
}

/**
 * Các thông tin hiện tại của người dùng
 */
interface CurrentUserContext {
  userId: number
  sessionId: string
  deviceId: number
  email?: string
}

/**
 * Controller quản lý phiên đăng nhập và thiết bị
 */
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
    this.logger.debug(`[getSessions] Getting session list for userId ${activeUser.userId}`)
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
  ): Promise<{ message: string; data: RevokeSessionsResponseDto | VerificationNeededResponseDto }> {
    const userContext = this.getUserContext(activeUser)
    const { sessionIds, deviceIds, excludeCurrentSession } = body

    this.logger.debug(`[revokeSessions] User ${userContext.userId} requests revocation.`)

    const revocationOptions = { sessionIds, deviceIds, excludeCurrentSession }
    const requiresVerification = await this.sessionsService.checkIfActionRequiresVerification(
      userContext.userId,
      revocationOptions
    )

    if (requiresVerification) {
      this.logger.debug(`[revokeSessions] Additional verification required for user ${userContext.userId}`)
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
        data: {
          verificationType: verificationResult.verificationType
        }
      }
    }

    const result = await this.sessionsService.revokeItems(userContext.userId, revocationOptions, userContext)
    return {
      message: result.message,
      data: {
        revokedSessionsCount: result.revokedSessionsCount,
        untrustedDevicesCount: result.untrustedDevicesCount
      }
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
  ): Promise<{ message: string; data: VerificationNeededResponseDto }> {
    const userContext = this.getUserContext(activeUser)
    this.logger.debug(`[revokeAllSessions] User ${userContext.userId} requests to revoke all sessions.`)

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
      data: {
        verificationType: verificationResult.verificationType
      }
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
  ): Promise<{ message: string; data: UpdateDeviceNameResponseDto }> {
    this.logger.debug(
      `[updateDeviceName] User ${activeUser.userId} updating device name ${params.deviceId} to "${body.name}"`
    )
    await this.sessionsService.updateDeviceName(activeUser.userId, params.deviceId, body.name)
    return {
      message: 'auth.Auth.Device.NameUpdated',
      data: {
        deviceId: params.deviceId,
        name: body.name
      }
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
  ): Promise<{ message: string; data: { deviceId: number } }> {
    this.logger.debug(`[untrustDevice] User ${activeUser.userId} untrusting device ${params.deviceId}`)
    await this.sessionsService.untrustDevice(activeUser.userId, params.deviceId)
    return {
      message: 'auth.Auth.Device.Untrusted',
      data: {
        deviceId: params.deviceId
      }
    }
  }
}
