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
  Logger,
  Ip,
  Res
} from '@nestjs/common'
import { SessionsService } from './sessions.service'
import { AccessTokenGuard } from 'src/routes/auth/guards/access-token.guard'
import { ActiveUser } from 'src/routes/auth/decorators/active-user.decorator'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'
import { UserAgent } from 'src/shared/decorators/user-agent.decorator'
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
  UntrustDeviceResponseDto,
  RevokeAllSessionsBodyDto
} from './dto/session.dto'
import { I18nService } from 'nestjs-i18n'
import { DynamicZodSerializer } from 'src/shared/interceptor/dynamic-zod-serializer.interceptor'
import { TypeOfVerificationCode } from 'src/routes/auth/constants/auth.constants'
import { Response } from 'express'
import { OtpService } from '../../modules/otp/otp.service'

@UseGuards(AccessTokenGuard)
@Controller('auth/sessions')
export class SessionsController {
  private readonly logger = new Logger(SessionsController.name)

  constructor(
    private readonly sessionsService: SessionsService,
    private readonly i18nService: I18nService,
    private readonly otpService: OtpService
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
          excludeCurrentSession: body.excludeCurrentSession
        }
      })

      // Đặt SLT cookie
      this.otpService.setSltCookie(res, sltToken, TypeOfVerificationCode.REVOKE_SESSIONS)

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

    // Trường hợp xử lý thu hồi một session duy nhất (backward compatibility)
    if (body.sessionIds?.length === 1 && !body.deviceIds?.length) {
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
          requiresAdditionalVerification: false
        }
      }
    }

    // Nếu không cần xác thực thêm, thực hiện thu hồi ngay
    const result = await this.sessionsService.revokeItems(
      activeUser.userId,
      {
        sessionIds: body.sessionIds,
        deviceIds: body.deviceIds,
        excludeCurrentSession: body.excludeCurrentSession
      },
      activeUser,
      undefined,
      undefined,
      ip,
      userAgent
    )

    return {
      statusCode: HttpStatus.OK,
      message: result.message,
      data: {
        revokedSessionsCount: result.revokedSessionsCount,
        untrustedDevicesCount: result.untrustedDevicesCount,
        revokedSessionIds: result.revokedSessionIds || [],
        revokedDeviceIds: result.revokedDeviceIds || [],
        requiresAdditionalVerification: false
      }
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
        excludeCurrentSession: body.excludeCurrentSession
      }
    })

    // Đặt SLT cookie
    this.otpService.setSltCookie(res, sltToken, TypeOfVerificationCode.REVOKE_ALL_SESSIONS)

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
}
