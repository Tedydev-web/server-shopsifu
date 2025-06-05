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
  Req
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
import { Response, Request } from 'express'
import { OtpService } from '../../modules/otp/otp.service'
import { ICookieService } from 'src/shared/types/auth.types'
import { COOKIE_SERVICE } from 'src/shared/constants/injection.tokens'
import { I18nTranslations, I18nPath } from 'src/generated/i18n.generated'
import { HttpException } from '@nestjs/common'
import { AuthError } from '../../auth.error'
import { TwoFactorService } from '../two-factor/two-factor.service'
import { User } from '@prisma/client'

@Controller('auth/sessions')
export class SessionsController {
  private readonly logger = new Logger(SessionsController.name)

  constructor(
    private readonly sessionsService: SessionsService,
    private readonly i18nService: I18nService<I18nTranslations>,
    private readonly otpService: OtpService,
    @Inject(COOKIE_SERVICE) private readonly cookieService: ICookieService,
    private readonly twoFactorService: TwoFactorService
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
    @Res({ passthrough: true }) res: Response,
    @Req() req: Request
  ): Promise<{
    statusCode: number
    message: string
    data: RevokeSessionsResponseDto
  }> {
    this.logger.debug(
      `[Revoke Sessions] User ${activeUser.userId} attempting to revoke items. SessionIds: ${JSON.stringify(body.sessionIds ?? 'N/A')}, DeviceIds: ${JSON.stringify(body.deviceIds ?? 'N/A')}, ExcludeCurrent: ${body.excludeCurrentSession}`
    )
    try {
      const currentSessionId = activeUser.sessionId
      const requiresVerification = await this.sessionsService.checkIfActionRequiresVerification(activeUser.userId, {
        sessionIds: body.sessionIds,
        deviceIds: body.deviceIds,
        excludeCurrentSession: body.excludeCurrentSession
      })

      if (requiresVerification) {
        this.logger.debug(`[Revoke Sessions] User ${activeUser.userId} requires additional verification.`)

        let sltToken: string
        let verificationPurpose: TypeOfVerificationCode
        let responseVerificationType: 'OTP' | '2FA'

        const user = (await this.sessionsService.getUserById(activeUser.userId)) as User & {
          email: string
          twoFactorMethod: string | null
        }

        if (!user) {
          this.logger.error(`[Revoke Sessions] User not found: ${activeUser.userId}`)
          throw AuthError.EmailNotFound()
        }

        if (user.twoFactorEnabled && user.twoFactorMethod) {
          this.logger.debug(
            `[Revoke Sessions] User ${activeUser.userId} has 2FA enabled (${user.twoFactorMethod}). Initiating 2FA.`
          )
          verificationPurpose = TypeOfVerificationCode.REVOKE_SESSIONS_2FA
          responseVerificationType = '2FA'
          sltToken = await this.twoFactorService.initiateTwoFactorActionWithSltCookie({
            userId: activeUser.userId,
            deviceId: activeUser.deviceId,
            ipAddress: ip,
            userAgent,
            purpose: verificationPurpose,
            metadata: {
              sessionIds: body.sessionIds,
              deviceIds: body.deviceIds,
              revokeAllUserSessions: false,
              excludeCurrentSession: body.excludeCurrentSession,
              currentSessionIdToExclude: currentSessionId,
              currentDeviceIdToExclude: activeUser.deviceId,
              actionType: 'revoke_sessions'
            }
          })
        } else {
          this.logger.debug(`[Revoke Sessions] User ${activeUser.userId} does NOT have 2FA. Initiating OTP.`)
          verificationPurpose = TypeOfVerificationCode.REVOKE_SESSIONS
          responseVerificationType = 'OTP'
          sltToken = await this.otpService.initiateOtpWithSltCookie({
            email: user.email,
            userId: activeUser.userId,
            deviceId: activeUser.deviceId,
            ipAddress: ip,
            userAgent,
            purpose: verificationPurpose,
            metadata: {
              sessionIds: body.sessionIds,
              deviceIds: body.deviceIds,
              revokeAllUserSessions: false,
              excludeCurrentSession: body.excludeCurrentSession,
              currentSessionIdToExclude: currentSessionId,
              currentDeviceIdToExclude: activeUser.deviceId,
              actionType: 'revoke_sessions'
            }
          })
        }

        this.cookieService.setSltCookie(res, sltToken, verificationPurpose)

        return {
          statusCode: HttpStatus.OK,
          message: this.i18nService.t('auth.Auth.Session.RequiresAdditionalVerification', {
            lang: (req as any).i18nLang
          }),
          data: {
            requiresAdditionalVerification: true,
            verificationType: responseVerificationType,
            revokedSessionsCount: 0,
            untrustedDevicesCount: 0,
            revokedSessionIds: [],
            revokedDeviceIds: []
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
        { sessionId: currentSessionId, deviceId: activeUser.deviceId },
        undefined,
        undefined,
        ip,
        userAgent
      )

      return {
        statusCode: HttpStatus.OK,
        message: result.message
          ? this.i18nService.t(result.message as I18nPath, { lang: (req as any).i18nLang })
          : this.i18nService.t('auth.Auth.Otp.Verified', { lang: (req as any).i18nLang }),
        data: {
          revokedSessionsCount: result.revokedSessionsCount,
          untrustedDevicesCount: result.untrustedDevicesCount,
          revokedSessionIds: result.revokedSessionIds || [],
          revokedDeviceIds: result.revokedDeviceIds || [],
          requiresAdditionalVerification: false
        } as RevokeSessionsResponseDto
      }
    } catch (error) {
      this.logger.error(`[Revoke Sessions] Error for user ${activeUser.userId}: ${error.message}`, error.stack)
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
    @Res({ passthrough: true }) res: Response,
    @Req() req: Request
  ): Promise<{
    statusCode: number
    message: string
    data: RevokeSessionsResponseDto
  }> {
    this.logger.debug(
      `[Revoke All Sessions] User ${activeUser.userId} attempting to revoke all sessions. ExcludeCurrent: ${body.excludeCurrentSession}`
    )
    try {
      const currentSessionId = activeUser.sessionId
      const requiresVerification = await this.sessionsService.checkIfActionRequiresVerification(activeUser.userId, {
        revokeAllUserSessions: true,
        excludeCurrentSession: body.excludeCurrentSession
      })

      if (requiresVerification) {
        this.logger.debug(`[Revoke All Sessions] User ${activeUser.userId} requires additional verification.`)
        let sltToken: string
        let verificationPurpose: TypeOfVerificationCode
        let responseVerificationType: 'OTP' | '2FA'

        const user = (await this.sessionsService.getUserById(activeUser.userId)) as User & {
          email: string
          twoFactorMethod: string | null
        }

        if (!user) {
          this.logger.error(`[Revoke All Sessions] User not found: ${activeUser.userId}`)
          throw AuthError.EmailNotFound()
        }

        if (user.twoFactorEnabled && user.twoFactorMethod) {
          this.logger.debug(
            `[Revoke All Sessions] User ${activeUser.userId} has 2FA enabled (${user.twoFactorMethod}). Initiating 2FA.`
          )
          verificationPurpose = TypeOfVerificationCode.REVOKE_ALL_SESSIONS_2FA
          responseVerificationType = '2FA'
          sltToken = await this.twoFactorService.initiateTwoFactorActionWithSltCookie({
            userId: activeUser.userId,
            deviceId: activeUser.deviceId,
            ipAddress: ip,
            userAgent,
            purpose: verificationPurpose,
            metadata: {
              revokeAllUserSessions: true,
              excludeCurrentSession: body.excludeCurrentSession,
              currentSessionIdToExclude: currentSessionId,
              currentDeviceIdToExclude: activeUser.deviceId,
              actionType: 'revoke_all_sessions'
            }
          })
        } else {
          this.logger.debug(`[Revoke All Sessions] User ${activeUser.userId} does NOT have 2FA. Initiating OTP.`)
          verificationPurpose = TypeOfVerificationCode.REVOKE_ALL_SESSIONS
          responseVerificationType = 'OTP'
          sltToken = await this.otpService.initiateOtpWithSltCookie({
            email: user.email,
            userId: activeUser.userId,
            deviceId: activeUser.deviceId,
            ipAddress: ip,
            userAgent,
            purpose: verificationPurpose,
            metadata: {
              revokeAllUserSessions: true,
              excludeCurrentSession: body.excludeCurrentSession,
              currentSessionIdToExclude: currentSessionId,
              currentDeviceIdToExclude: activeUser.deviceId,
              actionType: 'revoke_all_sessions'
            }
          })
        }

        this.cookieService.setSltCookie(res, sltToken, verificationPurpose)

        return {
          statusCode: HttpStatus.OK,
          message: this.i18nService.t('auth.Auth.Session.RequiresAdditionalVerification', {
            lang: (req as any).i18nLang
          }),
          data: {
            requiresAdditionalVerification: true,
            verificationType: responseVerificationType,
            revokedSessionsCount: 0,
            untrustedDevicesCount: 0,
            revokedSessionIds: [],
            revokedDeviceIds: []
          } as RevokeSessionsResponseDto
        }
      }

      const result = await this.sessionsService.revokeItems(
        activeUser.userId,
        {
          revokeAllUserSessions: true,
          excludeCurrentSession: body.excludeCurrentSession
        },
        { sessionId: currentSessionId, deviceId: activeUser.deviceId },
        undefined,
        undefined,
        ip,
        userAgent
      )
      return {
        statusCode: HttpStatus.OK,
        message: result.message
          ? this.i18nService.t(result.message as I18nPath, { lang: (req as any).i18nLang })
          : this.i18nService.t('auth.Auth.Session.AllRevoked', { lang: (req as any).i18nLang }),
        data: {
          revokedSessionsCount: result.revokedSessionsCount,
          untrustedDevicesCount: result.untrustedDevicesCount,
          revokedSessionIds: result.revokedSessionIds || [],
          revokedDeviceIds: result.revokedDeviceIds || [],
          requiresAdditionalVerification: false
        } as RevokeSessionsResponseDto
      }
    } catch (error) {
      this.logger.error(`[Revoke All Sessions] Error for user ${activeUser.userId}: ${error.message}`, error.stack)
      if (error instanceof HttpException) throw error
      throw AuthError.InternalServerError(error.message)
    }
  }

  @Patch('devices/:deviceId/name')
  @HttpCode(HttpStatus.OK)
  async updateDeviceName(
    @ActiveUser() activeUser: AccessTokenPayload,
    @Param() params: DeviceIdParamsDto,
    @Body() body: UpdateDeviceNameBodyDto,
    @Req() req: Request
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
          ? this.i18nService.t(result.message as I18nPath, {
              lang: (req as any).i18nLang
            })
          : this.i18nService.t('auth.Auth.Otp.Verified', {
              lang: (req as any).i18nLang
            }),
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
    @UserAgent() userAgent: string,
    @Req() req: Request
  ): Promise<{
    statusCode: number
    message: string
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
          ? this.i18nService.t(result.message as I18nPath, {
              lang: (req as any).i18nLang
            })
          : this.i18nService.t('auth.Auth.Otp.Verified', {
              lang: (req as any).i18nLang
            })
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
    @Param() params: DeviceIdParamsDto,
    @Req() req: Request
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
          ? this.i18nService.t(result.message as I18nPath, {
              lang: (req as any).i18nLang
            })
          : this.i18nService.t('auth.Auth.Otp.Verified', {
              lang: (req as any).i18nLang
            }),
        data: result
      }
    } catch (error) {
      if (error instanceof HttpException) throw error
      throw AuthError.InternalServerError(error.message)
    }
  }
}
