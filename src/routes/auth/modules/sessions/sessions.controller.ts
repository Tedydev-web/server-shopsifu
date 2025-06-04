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
  Inject
} from '@nestjs/common'
import { SessionsService } from './sessions.service'
import { ActiveUser } from 'src/shared/decorators/active-user.decorator'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'
import { UserAgent } from 'src/shared/decorators/user-agent.decorator'
import {
  GetSessionsQueryDto,
  GetGroupedSessionsResponseDto,
  RevokeSessionsBodyDto,
  RevokeSessionsResponseDto,
  DeviceIdParamsDto,
  UpdateDeviceNameBodyDto,
  UpdateDeviceNameResponseDto,
  TrustDeviceResponseDto,
  UntrustDeviceResponseDto,
  RevokeAllSessionsBodyDto
} from './session.dto'
import { I18nService } from 'nestjs-i18n'
import { DynamicZodSerializer } from 'src/shared/interceptor/dynamic-zod-serializer.interceptor'
import { TypeOfVerificationCode } from 'src/shared/constants/auth.constants'
import { Response } from 'express'
import { OtpService } from '../../modules/otp/otp.service'
import { ICookieService } from 'src/shared/types/auth.types'
import { COOKIE_SERVICE } from 'src/shared/constants/injection.tokens'
import { I18nTranslations, I18nPath } from 'src/generated/i18n.generated'
import { HttpException } from '@nestjs/common'
import { AuthError } from '../../auth.error'

@Controller('auth/sessions')
export class SessionsController {
  private readonly logger = new Logger(SessionsController.name)

  constructor(
    private readonly sessionsService: SessionsService,
    private readonly i18nService: I18nService<I18nTranslations>,
    private readonly otpService: OtpService,
    @Inject(COOKIE_SERVICE) private readonly cookieService: ICookieService
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
    try {
      return await this.sessionsService.getSessions(activeUser.userId, query.page, query.limit, activeUser.sessionId)
    } catch (error) {
      this.logger.error(`[SessionsController.getSessions] Error: ${error.message}`, error.stack)
      if (error instanceof HttpException) throw error
      throw AuthError.InternalServerError(error.message)
    }
  }

  /**
   * Thu hồi sessions và devices cụ thể
   * Endpoint này xử lý việc thu hồi một hoặc nhiều session/device cụ thể:
   * 1. Thu hồi một session cụ thể
   * 2. Thu hồi nhiều session cụ thể
   * 3. Thu hồi một hoặc nhiều device cụ thể (và các session liên quan)
   *
   * Nếu cần xác thực bổ sung, tạo SLT token và chuyển hướng đến 2FA/OTP
   */
  @Post('revoke')
  @HttpCode(HttpStatus.OK)
  async revokeSessions(
    @ActiveUser() activeUser: AccessTokenPayload,
    @Body() body: RevokeSessionsBodyDto,
    @UserAgent() userAgent: string,
    @Ip() ip: string,
    @Res({ passthrough: true }) res: Response
  ): Promise<{
    statusCode: number
    message: string
    data: RevokeSessionsResponseDto
  }> {
    this.logger.debug(
      `[SessionsController.revokeSessions] User ${activeUser.userId} revoking sessions/devices with: ${JSON.stringify(body)}`
    )
    try {
      // Kiểm tra xem hành động này có yêu cầu xác thực bổ sung không
      const requiresVerification = await this.sessionsService.checkIfActionRequiresVerification(activeUser.userId, {
        sessionIds: body.sessionIds,
        deviceIds: body.deviceIds,
        excludeCurrentSession: body.excludeCurrentSession
      })

      if (requiresVerification) {
        // Tạo SLT token với context data chứa thông tin thu hồi
        const sltToken = await this.otpService.initiateOtpWithSltCookie({
          email: activeUser.email || '',
          userId: activeUser.userId,
          deviceId: activeUser.deviceId,
          ipAddress: ip,
          userAgent: userAgent,
          purpose: TypeOfVerificationCode.REVOKE_SESSIONS,
          metadata: {
            sessionIds: body.sessionIds,
            deviceIds: body.deviceIds,
            excludeCurrentSession: body.excludeCurrentSession,
            currentSessionIdToExclude: activeUser.sessionId,
            currentDeviceIdToExclude: activeUser.deviceId
          }
        })

        this.cookieService.setSltCookie(res, sltToken, TypeOfVerificationCode.REVOKE_SESSIONS)

        const user = await this.sessionsService.getUserById(activeUser.userId)

        return {
          statusCode: HttpStatus.OK,
          message: await this.i18nService.translate('Auth.Session.RequiresAdditionalVerification' as I18nPath),
          data: {
            revokedSessionsCount: 0,
            untrustedDevicesCount: 0,
            revokedSessionIds: [],
            revokedDeviceIds: [],
            requiresAdditionalVerification: true,
            verificationType: user.twoFactorEnabled ? '2FA' : 'OTP'
          } as RevokeSessionsResponseDto
        }
      }

      // Luôn gọi revokeItems.
      const result = await this.sessionsService.revokeItems(
        activeUser.userId,
        {
          sessionIds: body.sessionIds,
          deviceIds: body.deviceIds,
          excludeCurrentSession: body.excludeCurrentSession
        },
        { sessionId: activeUser.sessionId, deviceId: activeUser.deviceId }, // Truyền currentSessionDetails
        undefined, // verificationToken - sẽ được xử lý bởi OTP flow nếu có
        undefined, // otpCode - sẽ được xử lý bởi OTP flow nếu có
        ip,
        userAgent
      )

      return {
        statusCode: HttpStatus.OK,
        message: result.message
          ? await this.i18nService.translate(result.message as I18nPath)
          : 'Error retrieving message for revokeItems',
        data: {
          revokedSessionsCount: result.revokedSessionsCount,
          untrustedDevicesCount: result.untrustedDevicesCount,
          revokedSessionIds: result.revokedSessionIds || [],
          revokedDeviceIds: result.revokedDeviceIds || [],
          requiresAdditionalVerification: false
        }
      }
    } catch (error) {
      this.logger.error(`[SessionsController.revokeSessions] Error: ${error.message}`, error.stack)
      if (error instanceof HttpException) throw error
      throw AuthError.InternalServerError(error.message)
    }
  }

  /**
   * Thu hồi tất cả phiên đăng nhập
   * Endpoint riêng cho việc thu hồi tất cả phiên đăng nhập.
   * Có thể loại trừ phiên đăng nhập hiện tại để tránh người dùng bị đăng xuất.
   * Luôn yêu cầu xác thực bổ sung.
   */
  @Post('revoke-all')
  @HttpCode(HttpStatus.OK)
  async revokeAllSessions(
    @ActiveUser() activeUser: AccessTokenPayload,
    @Body() body: RevokeAllSessionsBodyDto,
    @UserAgent() userAgent: string,
    @Ip() ip: string,
    @Res({ passthrough: true }) res: Response
  ): Promise<{
    statusCode: number
    message: string
    data: RevokeSessionsResponseDto
  }> {
    this.logger.debug(
      `[SessionsController.revokeAllSessions] User ${activeUser.userId} revoking all sessions with excludeCurrentSession=${body.excludeCurrentSession}`
    )
    try {
      // Thu hồi tất cả luôn yêu cầu xác thực bổ sung
      // Tạo SLT token với context data chứa thông tin thu hồi tất cả
      const sltToken = await this.otpService.initiateOtpWithSltCookie({
        email: activeUser.email || '',
        userId: activeUser.userId,
        deviceId: activeUser.deviceId,
        ipAddress: ip,
        userAgent: userAgent,
        purpose: TypeOfVerificationCode.REVOKE_ALL_SESSIONS,
        metadata: {
          revokeAllUserSessions: true,
          excludeCurrentSession: body.excludeCurrentSession,
          currentSessionIdToExclude: activeUser.sessionId,
          currentDeviceIdToExclude: activeUser.deviceId
        }
      })

      // Đặt SLT cookie
      this.cookieService.setSltCookie(res, sltToken, TypeOfVerificationCode.REVOKE_ALL_SESSIONS)

      const user = await this.sessionsService.getUserById(activeUser.userId)

      return {
        statusCode: HttpStatus.OK,
        message: await this.i18nService.translate('Auth.Session.RequiresAdditionalVerification' as I18nPath),
        data: {
          revokedSessionsCount: 0,
          untrustedDevicesCount: 0,
          revokedSessionIds: [],
          revokedDeviceIds: [],
          requiresAdditionalVerification: true,
          verificationType: user.twoFactorEnabled ? '2FA' : 'OTP'
        } as RevokeSessionsResponseDto
      }
    } catch (error) {
      this.logger.error(`[SessionsController.revokeAllSessions] Error: ${error.message}`, error.stack)
      if (error instanceof HttpException) throw error
      throw AuthError.InternalServerError(error.message)
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
    try {
      const result = await this.sessionsService.updateDeviceName(activeUser.userId, params.deviceId, body.name)

      return {
        statusCode: HttpStatus.OK,
        message: result.message
          ? await this.i18nService.translate(result.message as I18nPath)
          : 'Error retrieving message for updateDeviceName',
        data: result
      }
    } catch (error) {
      this.logger.error(`[SessionsController.updateDeviceName] Error: ${error.message}`, error.stack)
      if (error instanceof HttpException) throw error
      throw AuthError.InternalServerError(error.message)
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
    try {
      const result = await this.sessionsService.trustCurrentDevice(
        activeUser.userId,
        activeUser.deviceId,
        ip,
        userAgent
      )

      return {
        statusCode: HttpStatus.OK,
        message: result.message
          ? await this.i18nService.translate(result.message as I18nPath)
          : 'Error retrieving message for trustCurrentDevice',
        data: result
      }
    } catch (error) {
      this.logger.error(`[SessionsController.trustCurrentDevice] Error: ${error.message}`, error.stack)
      if (error instanceof HttpException) throw error
      throw AuthError.InternalServerError(error.message)
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
    try {
      const result = await this.sessionsService.untrustDevice(activeUser.userId, params.deviceId)

      return {
        statusCode: HttpStatus.OK,
        message: result.message
          ? await this.i18nService.translate(result.message as I18nPath)
          : 'Error retrieving message for untrustDevice',
        data: result
      }
    } catch (error) {
      this.logger.error(`[SessionsController.untrustDevice] Error: ${error.message}`, error.stack)
      if (error instanceof HttpException) throw error
      throw AuthError.InternalServerError(error.message)
    }
  }
}
