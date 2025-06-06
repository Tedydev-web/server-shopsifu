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
  HttpException,
  forwardRef
} from '@nestjs/common'
import { SessionsService } from './sessions.service'
import { ActiveUser } from 'src/routes/auth/shared/decorators/active-user.decorator'
import { AccessTokenPayload, ICookieService } from 'src/routes/auth/shared/auth.types'
import { UserAgent } from 'src/shared/decorators/user-agent.decorator'
import {
  GetSessionsQueryDto,
  GetGroupedSessionsResponseDto,
  RevokeSessionsBodyDto,
  DeviceIdParamsDto,
  UpdateDeviceNameBodyDto,
  UpdateDeviceNameResponseDto,
  UntrustDeviceResponseDto,
  RevokeAllSessionsBodyDto
} from './session.dto'
import { I18nService } from 'nestjs-i18n'
import { TypeOfVerificationCode } from 'src/routes/auth/shared/constants/auth.constants'
import { Response, Request } from 'express'
import { COOKIE_SERVICE } from 'src/shared/constants/injection.tokens'
import { I18nTranslations, I18nPath } from 'src/generated/i18n.generated'
import { AuthError } from '../../auth.error'
import { Auth } from 'src/routes/auth/shared/decorators/auth.decorator'
import { AuthVerificationService } from '../../services/auth-verification.service'

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
    private readonly i18nService: I18nService<I18nTranslations>,
    @Inject(forwardRef(() => AuthVerificationService))
    private readonly authVerificationService: AuthVerificationService,
    @Inject(COOKIE_SERVICE) private readonly cookieService: ICookieService
  ) {}

  /**
   * Lấy tất cả sessions của người dùng, nhóm theo thiết bị
   */
  @Get()
  @HttpCode(HttpStatus.OK)
  async getSessions(
    @ActiveUser() activeUser: AccessTokenPayload,
    @Query() query: GetSessionsQueryDto
  ): Promise<GetGroupedSessionsResponseDto> {
    try {
      this.logger.debug(`[getSessions] Lấy danh sách phiên đăng nhập cho userId ${activeUser.userId}`)
      return await this.sessionsService.getSessions(activeUser.userId, query.page, query.limit, activeUser.sessionId)
    } catch (error) {
      this.handleError(error, 'getSessions')
    }
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
    @Res({ passthrough: true }) res: Response,
    @Req() req: Request
  ): Promise<any> {
    try {
      const userContext = this.getUserContext(activeUser)
      const { sessionIds, deviceIds, excludeCurrentSession } = body

      this.logger.debug(
        `[revokeSessions] User ${userContext.userId} requests revocation - ` +
          `SessionIds: ${JSON.stringify(sessionIds ?? [])}, ` +
          `DeviceIds: ${JSON.stringify(deviceIds ?? [])}, ` +
          `ExcludeCurrent: ${excludeCurrentSession}`
      )

      const revocationOptions = { sessionIds, deviceIds, excludeCurrentSession }

      const requiresVerification = await this.sessionsService.checkIfActionRequiresVerification(
        userContext.userId,
        revocationOptions
      )

      if (requiresVerification) {
        this.logger.debug(`[revokeSessions] Additional verification required for user ${userContext.userId}`)

        if (!activeUser.email) {
          throw AuthError.InternalServerError('Active user email missing in token for session revocation.')
        }

        const verificationResult = await this.authVerificationService.initiateVerification(
          {
            userId: userContext.userId,
            deviceId: userContext.deviceId,
            email: activeUser.email,
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
            requiresAdditionalVerification: true,
            verificationType: verificationResult.verificationType
          }
        }
      }

      // If no verification is needed, proceed with revocation.
      const result = await this.sessionsService.revokeItems(userContext.userId, revocationOptions, userContext)

      return {
        message: result.message || this.i18nService.t('auth.Auth.Session.RevokedSuccessfully' as I18nPath),
        data: {
          revokedSessionsCount: result.revokedSessionsCount,
          untrustedDevicesCount: result.untrustedDevicesCount
        }
      }
    } catch (error) {
      this.handleError(error, 'revokeSessions')
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
    @Res({ passthrough: true }) res: Response,
    @Req() req: Request
  ): Promise<any> {
    try {
      const userContext = this.getUserContext(activeUser)
      this.logger.debug(
        `[revokeAllSessions] User ${userContext.userId} requests to revoke all sessions. ExcludeCurrent: ${body.excludeCurrentSession}`
      )

      if (!activeUser.email) {
        throw AuthError.InternalServerError('Active user email missing in token for session revocation.')
      }

      const verificationResult = await this.authVerificationService.initiateVerification(
        {
          userId: userContext.userId,
          deviceId: userContext.deviceId,
          email: activeUser.email,
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
          requiresAdditionalVerification: true,
          verificationType: verificationResult.verificationType
        }
      }
    } catch (error) {
      this.handleError(error, 'revokeAllSessions')
    }
  }

  /**
   * Tạo đối tượng UserContext từ AccessTokenPayload
   */
  private getUserContext(activeUser: AccessTokenPayload): CurrentUserContext {
    return {
      userId: activeUser.userId,
      sessionId: activeUser.sessionId,
      deviceId: activeUser.deviceId
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
  ): Promise<any> {
    try {
      this.logger.debug(
        `[updateDeviceName] User ${activeUser.userId} cập nhật tên thiết bị ${params.deviceId}: "${body.name}"`
      )

      await this.sessionsService.updateDeviceName(activeUser.userId, params.deviceId, body.name)

      return {
        message: await this.i18nService.t('auth.Auth.Device.NameUpdated' as I18nPath),
        data: {
          deviceId: params.deviceId,
          name: body.name,
          success: true
        }
      }
    } catch (error) {
      return this.handleError(error, 'updateDeviceName')
    }
  }

  /**
   * Đánh dấu thiết bị hiện tại là đáng tin cậy
   */
  @Patch('current-device/trust')
  @HttpCode(HttpStatus.OK)
  async trustCurrentDevice(
    @ActiveUser() activeUser: AccessTokenPayload,
    @Ip() ip: string,
    @UserAgent() userAgent: string
  ): Promise<any> {
    try {
      this.logger.debug(
        `[trustCurrentDevice] User ${activeUser.userId} đánh dấu tin cậy thiết bị hiện tại ${activeUser.deviceId}`
      )

      await this.sessionsService.trustCurrentDevice(activeUser.userId, activeUser.deviceId)

      return {
        message: await this.i18nService.t('auth.Auth.Device.Trusted' as I18nPath)
      }
    } catch (error) {
      return this.handleError(error, 'trustCurrentDevice')
    }
  }

  /**
   * Hủy bỏ trạng thái đáng tin cậy của thiết bị
   */
  @Patch('devices/:deviceId/untrust')
  @HttpCode(HttpStatus.OK)
  async untrustDevice(@ActiveUser() activeUser: AccessTokenPayload, @Param() params: DeviceIdParamsDto): Promise<any> {
    try {
      this.logger.debug(`[untrustDevice] User ${activeUser.userId} hủy bỏ tin cậy thiết bị ${params.deviceId}`)

      await this.sessionsService.untrustDevice(activeUser.userId, params.deviceId)

      return {
        message: await this.i18nService.t('auth.Auth.Device.Untrusted' as I18nPath),
        data: {
          deviceId: params.deviceId,
          success: true
        }
      }
    } catch (error) {
      return this.handleError(error, 'untrustDevice')
    }
  }

  /**
   * Xử lý lỗi tập trung
   */
  private handleError(error: any, methodName: string): never {
    this.logger.error(`[${methodName}] Lỗi: ${error.message}`, error.stack)

    if (error instanceof HttpException) {
      throw error
    }

    throw AuthError.InternalServerError(error.message)
  }
}
