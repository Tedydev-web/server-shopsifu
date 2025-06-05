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
    try {
      return await this.sessionsService.getSessions(activeUser.userId, query.page, query.limit, activeUser.sessionId)
    } catch (error) {
      if (error instanceof HttpException) throw error
      throw AuthError.InternalServerError(error.message)
    }
  }

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
    try {
      const requiresVerification = await this.sessionsService.checkIfActionRequiresVerification(activeUser.userId, {
        sessionIds: body.sessionIds,
        deviceIds: body.deviceIds,
        excludeCurrentSession: body.excludeCurrentSession
      })

      if (requiresVerification) {
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
          message: this.i18nService.t('auth.Auth.Session.RequiresAdditionalVerification'),
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
          ? this.i18nService.t(result.message as I18nPath)
          : this.i18nService.t('auth.Auth.Otp.Verified'),
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
        message: this.i18nService.t('auth.Auth.Session.RequiresAdditionalVerification'),
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
    try {
      const result = await this.sessionsService.updateDeviceName(activeUser.userId, params.deviceId, body.name)

      return {
        statusCode: HttpStatus.OK,
        message: result.message
          ? this.i18nService.t(result.message as I18nPath)
          : this.i18nService.t('auth.Auth.Otp.Verified'),
        data: result
      }
    } catch (error) {
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
          ? this.i18nService.t(result.message as I18nPath)
          : this.i18nService.t('auth.Auth.Otp.Verified'),
        data: result
      }
    } catch (error) {
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
    try {
      const result = await this.sessionsService.untrustDevice(activeUser.userId, params.deviceId)

      return {
        statusCode: HttpStatus.OK,
        message: result.message
          ? this.i18nService.t(result.message as I18nPath)
          : this.i18nService.t('auth.Auth.Otp.Verified'),
        data: result
      }
    } catch (error) {
      if (error instanceof HttpException) throw error
      throw AuthError.InternalServerError(error.message)
    }
  }
}
