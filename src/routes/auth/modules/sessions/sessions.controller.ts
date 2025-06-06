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
  HttpException
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
import { AuthError } from '../../auth.error'
import { TwoFactorService } from '../two-factor/two-factor.service'
import { User } from '@prisma/client'

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

  /**
   * Lấy tất cả sessions của người dùng, nhóm theo thiết bị
   */
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
  ): Promise<{
    statusCode: number
    message: string
    data: RevokeSessionsResponseDto
  }> {
    try {
      const userContext = this.getUserContext(activeUser)

      this.logger.debug(
        `[revokeSessions] User ${userContext.userId} yêu cầu thu hồi - ` +
          `SessionIds: ${JSON.stringify(body.sessionIds ?? [])}, ` +
          `DeviceIds: ${JSON.stringify(body.deviceIds ?? [])}, ` +
          `ExcludeCurrent: ${body.excludeCurrentSession}`
      )

      const revocationOptions = {
        sessionIds: body.sessionIds,
        deviceIds: body.deviceIds,
        excludeCurrentSession: body.excludeCurrentSession
      }

      // Kiểm tra xem hành động này có yêu cầu xác thực bổ sung hay không
      const requiresVerification = await this.sessionsService.checkIfActionRequiresVerification(
        userContext.userId,
        revocationOptions
      )

      if (requiresVerification) {
        // Xử lý flow xác minh trước khi thu hồi
        return this.handleVerificationForRevoke(
          userContext,
          revocationOptions,
          ip,
          userAgent,
          req,
          res,
          false // Không phải revoke tất cả
        )
      }

      // Nếu không cần xác minh, thực hiện thu hồi ngay lập tức
      return this.executeRevocation(userContext, revocationOptions, ip, userAgent, req)
    } catch (error) {
      return this.handleError(error, 'revokeSessions')
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
  ): Promise<{
    statusCode: number
    message: string
    data: RevokeSessionsResponseDto
  }> {
    try {
      const userContext = this.getUserContext(activeUser)

      this.logger.debug(
        `[revokeAllSessions] User ${userContext.userId} yêu cầu thu hồi tất cả phiên, ExcludeCurrent: ${body.excludeCurrentSession}`
      )

      // Thu hồi tất cả phiên luôn yêu cầu xác minh
      return this.handleVerificationForRevoke(
        userContext,
        {
          excludeCurrentSession: body.excludeCurrentSession,
          revokeAllUserSessions: true
        },
        ip,
        userAgent,
        req,
        res,
        true // Là revoke tất cả
      )
    } catch (error) {
      return this.handleError(error, 'revokeAllSessions')
    }
  }

  /**
   * Xử lý quy trình xác minh bổ sung cho việc thu hồi phiên
   */
  private async handleVerificationForRevoke(
    userContext: CurrentUserContext,
    revocationOptions: {
      sessionIds?: string[]
      deviceIds?: number[]
      excludeCurrentSession?: boolean
      revokeAllUserSessions?: boolean
    },
    ip: string,
    userAgent: string,
    req: Request,
    res: Response,
    isRevokeAll: boolean
  ): Promise<{
    statusCode: number
    message: string
    data: RevokeSessionsResponseDto
  }> {
    this.logger.debug(`[handleVerificationForRevoke] Yêu cầu xác minh bổ sung cho user ${userContext.userId}`)

    const user = await this.getUserWithTwoFactorMethod(userContext.userId)

    // Chuẩn bị metadata chung cho cả hai phương thức xác thực
    const revokeMetadata: RevokeMetadata = {
      sessionIds: revocationOptions.sessionIds,
      deviceIds: revocationOptions.deviceIds,
      revokeAllUserSessions: isRevokeAll || revocationOptions.revokeAllUserSessions,
      excludeCurrentSession: revocationOptions.excludeCurrentSession,
      currentSessionIdToExclude: userContext.sessionId,
      currentDeviceIdToExclude: userContext.deviceId,
      actionType:
        isRevokeAll || revocationOptions.revokeAllUserSessions
          ? 'ALL'
          : (revocationOptions.sessionIds?.length || 0) + (revocationOptions.deviceIds?.length || 0) > 1
            ? 'MULTIPLE'
            : 'SINGLE'
    }

    const verificationContext = await this.initializeVerificationProcess(
      user,
      userContext,
      revokeMetadata,
      isRevokeAll,
      ip,
      userAgent,
      res
    )

    // Tạo phản hồi cho client hiển thị màn hình xác minh thích hợp
    const verificationMessage = isRevokeAll
      ? await this.i18nService.t('auth.Auth.Info.Session.VerifyToRevokeAll' as I18nPath)
      : await this.i18nService.t('auth.Auth.Info.Session.VerifyToRevoke' as I18nPath)

    return {
      statusCode: HttpStatus.OK,
      message: verificationMessage as string,
      data: {
        requiresAdditionalVerification: true,
        verificationType: verificationContext.verificationType,
        revokedSessionsCount: 0,
        untrustedDevicesCount: 0,
        revokedSessionIds: [],
        revokedDeviceIds: []
      } as RevokeSessionsResponseDto
    }
  }

  /**
   * Khởi tạo quy trình xác thực dựa trên người dùng có 2FA hay không
   */
  private async initializeVerificationProcess(
    user: User & { email: string; twoFactorMethod: string | null },
    userContext: CurrentUserContext,
    revokeMetadata: RevokeMetadata,
    isRevokeAll: boolean,
    ip: string,
    userAgent: string,
    res: Response
  ): Promise<{ verificationType: 'OTP' | '2FA'; sltToken?: string }> {
    // Xác định purpose dựa trên hành động và phương thức xác thực
    let verificationPurpose: TypeOfVerificationCode
    let verificationType: 'OTP' | '2FA'
    let sltToken: string | undefined

    if (user.twoFactorMethod) {
      this.logger.debug(
        `[initializeVerificationProcess] User ${userContext.userId} sử dụng 2FA (${user.twoFactorMethod}), yêu cầu xác minh 2FA`
      )

      // Khởi tạo quy trình 2FA
      verificationPurpose = isRevokeAll
        ? TypeOfVerificationCode.REVOKE_ALL_SESSIONS_2FA
        : TypeOfVerificationCode.REVOKE_SESSIONS_2FA

      sltToken = await this.twoFactorService.initiateTwoFactorActionWithSltCookie({
        userId: userContext.userId,
        deviceId: userContext.deviceId,
        ipAddress: ip,
        userAgent,
        purpose: verificationPurpose,
        metadata: revokeMetadata
      })

      this.cookieService.setSltCookie(res, sltToken, verificationPurpose)
      verificationType = '2FA'
    } else {
      this.logger.debug(
        `[initializeVerificationProcess] User ${userContext.userId} không sử dụng 2FA, gửi OTP xác minh`
      )

      // Sử dụng OTP cho người dùng không có 2FA
      verificationPurpose = isRevokeAll
        ? TypeOfVerificationCode.REVOKE_ALL_SESSIONS
        : TypeOfVerificationCode.REVOKE_SESSIONS

      // Tạo và gửi OTP
      await this.otpService.sendOTP(user.email, verificationPurpose, userContext.userId)
      verificationType = 'OTP'
    }

    return { verificationType, sltToken }
  }

  /**
   * Lấy thông tin người dùng bao gồm phương thức 2FA
   */
  private async getUserWithTwoFactorMethod(
    userId: number
  ): Promise<User & { email: string; twoFactorMethod: string | null }> {
    const user = (await this.sessionsService.getUserById(userId)) as unknown as User & {
      email: string
      twoFactorMethod: string | null
    }

    if (!user) {
      this.logger.error(`[getUserWithTwoFactorMethod] Không tìm thấy user: ${userId}`)
      throw AuthError.EmailNotFound()
    }

    return user
  }

  /**
   * Thực hiện thu hồi phiên sau khi đã xác minh hoặc không cần xác minh
   */
  private async executeRevocation(
    userContext: CurrentUserContext,
    options: {
      sessionIds?: string[]
      deviceIds?: number[]
      revokeAllUserSessions?: boolean
      excludeCurrentSession?: boolean
    },
    ip: string,
    userAgent: string,
    req: Request
  ): Promise<{
    statusCode: number
    message: string
    data: RevokeSessionsResponseDto
  }> {
    this.logger.debug(
      `[executeRevocation] Thực hiện thu hồi phiên cho userId ${userContext.userId}, revokeAll: ${options.revokeAllUserSessions}`
    )

    try {
      // Gọi service để thực hiện thu hồi
      const result = await this.sessionsService.revokeItems(
        userContext.userId,
        {
          sessionIds: options.sessionIds,
          deviceIds: options.deviceIds,
          revokeAllUserSessions: options.revokeAllUserSessions,
          excludeCurrentSession: options.excludeCurrentSession ?? true
        },
        {
          sessionId: userContext.sessionId,
          deviceId: userContext.deviceId
        },
        undefined,
        undefined,
        ip,
        userAgent
      )

      // Tạo thông báo phù hợp dựa trên loại thu hồi
      const messageKey = this.getRevocationSuccessMessageKey(options)
      const translatedMessage = await this.i18nService.t(messageKey as I18nPath)

      return {
        statusCode: HttpStatus.OK,
        message: translatedMessage as string,
        data: {
          revokedSessionsCount: result.revokedSessionsCount,
          untrustedDevicesCount: result.untrustedDevicesCount,
          revokedSessionIds: result.revokedSessionIds || [],
          revokedDeviceIds: result.revokedDeviceIds || [],
          requiresAdditionalVerification: false
        }
      }
    } catch (error) {
      return this.handleError(error, 'executeRevocation')
    }
  }

  /**
   * Lấy khóa thông báo thành công dựa trên loại thu hồi
   */
  private getRevocationSuccessMessageKey(options: {
    revokeAllUserSessions?: boolean
    excludeCurrentSession?: boolean
  }): string {
    if (options.revokeAllUserSessions) {
      return options.excludeCurrentSession
        ? 'auth.Auth.Success.Session.RevokedAllExceptCurrent'
        : 'auth.Auth.Success.Session.RevokedAll'
    }
    return 'auth.Auth.Success.Session.RevokedMultiple'
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
  ): Promise<{
    statusCode: number
    message: string
    data: UpdateDeviceNameResponseDto
  }> {
    try {
      this.logger.debug(
        `[updateDeviceName] User ${activeUser.userId} cập nhật tên thiết bị ${params.deviceId}: "${body.name}"`
      )

      await this.sessionsService.updateDeviceName(activeUser.userId, params.deviceId, body.name)

      return {
        statusCode: HttpStatus.OK,
        message: await this.i18nService.t('auth.Auth.Success.Device.NameUpdated' as I18nPath),
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
  ): Promise<{
    statusCode: number
    message: string
  }> {
    try {
      this.logger.debug(
        `[trustCurrentDevice] User ${activeUser.userId} đánh dấu tin cậy thiết bị hiện tại ${activeUser.deviceId}`
      )

      await this.sessionsService.trustCurrentDevice(activeUser.userId, activeUser.deviceId, ip, userAgent)

      return {
        statusCode: HttpStatus.OK,
        message: await this.i18nService.t('auth.Auth.Success.Device.Trusted' as I18nPath)
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
  async untrustDevice(
    @ActiveUser() activeUser: AccessTokenPayload,
    @Param() params: DeviceIdParamsDto
  ): Promise<{
    statusCode: number
    message: string
    data: UntrustDeviceResponseDto
  }> {
    try {
      this.logger.debug(`[untrustDevice] User ${activeUser.userId} hủy bỏ tin cậy thiết bị ${params.deviceId}`)

      await this.sessionsService.untrustDevice(activeUser.userId, params.deviceId)

      return {
        statusCode: HttpStatus.OK,
        message: await this.i18nService.t('auth.Auth.Success.Device.Untrusted' as I18nPath),
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
