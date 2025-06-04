import {
  Controller,
  Post,
  Body,
  Delete,
  Req,
  Res,
  HttpStatus,
  HttpCode,
  Logger,
  UnauthorizedException,
  BadRequestException,
  Ip,
  Inject,
  forwardRef
} from '@nestjs/common'
import { Request, Response } from 'express'
import { OtpService } from './otp.service'
import { CookieService } from 'src/shared/services/cookie.service'
import { I18nService } from 'nestjs-i18n'
import { AuthError } from '../../auth.error'
import { UserAgent } from 'src/shared/decorators/user-agent.decorator'
import { SendOtpDto, VerifyOtpDto, SendOtpResponseDto, VerifyOtpResponseDto } from './dto/otp.dto'
import { CoreService } from '../core/core.service'
import { TypeOfVerificationCode } from 'src/routes/auth/constants/auth.constants'
import { SltContextData } from 'src/routes/auth/auth.types'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'
import { SessionsService } from '../sessions/sessions.service'
import { CookieNames } from 'src/shared/constants/auth.constant'
import { IsPublic } from 'src/routes/auth/decorators/auth.decorator'
import { TokenService } from 'src/shared/services/token.service'

@Controller('auth/otp')
export class OtpController {
  private readonly logger = new Logger(OtpController.name)

  constructor(
    private readonly otpService: OtpService,
    private readonly cookieService: CookieService,
    private readonly i18nService: I18nService,
    private readonly coreService: CoreService,
    @Inject(forwardRef(() => SessionsService))
    private readonly sessionsService: SessionsService,
    private readonly tokenService: TokenService
  ) {}

  /**
   * Gửi OTP
   */
  @IsPublic()
  @Post('send')
  @HttpCode(HttpStatus.OK)
  async sendOtp(
    @Body() body: SendOtpDto,
    @Ip() ip: string,
    @UserAgent() userAgent: string,
    @Res({ passthrough: true }) res: Response
  ): Promise<SendOtpResponseDto> {
    const { email, type } = body

    // Khởi tạo OTP với SLT cookie
    const sltJwt = await this.otpService.initiateOtpWithSltCookie({
      email,
      userId: 0, // Được cập nhật sau khi tìm user
      deviceId: 0, // Được cập nhật sau khi tìm device
      ipAddress: ip,
      userAgent,
      purpose: type
    })

    // Set SLT cookie
    this.cookieService.setSltCookie(res, sltJwt, type)

    return {
      message: await this.i18nService.translate('Auth.Otp.SentSuccessfully')
    }
  }

  /**
   * Xác minh OTP
   */
  @IsPublic()
  @Post('verify')
  @HttpCode(HttpStatus.OK)
  async verifyOtp(
    @Body() body: VerifyOtpDto,
    @Ip() ip: string,
    @UserAgent() userAgent: string,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response
  ): Promise<any> {
    try {
      // Lấy SLT cookie từ request
      const sltCookieValue = req.cookies[CookieNames.SLT_TOKEN]
      if (!sltCookieValue) {
        throw AuthError.SLTCookieMissing()
      }

      // Xác minh OTP và SLT
      const sltContext = await this.otpService.verifySltOtpStage(sltCookieValue, body.code, ip, userAgent)

      // Xử lý dựa vào purpose trong SLT context
      switch (sltContext.purpose) {
        case TypeOfVerificationCode.LOGIN_UNTRUSTED_DEVICE_OTP:
          return await this.handleLoginVerification(sltContext, body, res, ip, userAgent)

        case TypeOfVerificationCode.REVOKE_SESSIONS:
          return await this.handleRevokeSessionsVerification(sltContext, ip, userAgent)

        case TypeOfVerificationCode.REVOKE_ALL_SESSIONS:
          return await this.handleRevokeAllSessionsVerification(sltContext, ip, userAgent)

        default:
          // Xóa SLT cookie vì đã hoàn tất quá trình xác minh
          this.cookieService.clearSltCookie(res)

          // Trả về thông báo xác minh thành công cho các loại OTP khác
          return {
            statusCode: HttpStatus.OK,
            message: await this.i18nService.translate('Auth.Otp.Verified'),
            data: { verified: true }
          }
      }
    } catch (error) {
      this.logger.error(`[verifyOtp] Error processing OTP verification: ${error.message}`, error.stack)
      throw error
    }
  }

  /**
   * Xử lý xác minh đăng nhập
   */
  private async handleLoginVerification(
    sltContext: SltContextData & { sltJti: string },
    body: VerifyOtpDto,
    res: Response,
    ip: string,
    userAgent: string
  ) {
    this.logger.debug(`[handleLoginVerification] Finalizing login for user ID: ${sltContext.userId}`)

    // Cập nhật SLT context để đánh dấu là đã hoàn thành
    await this.otpService.finalizeSlt(sltContext.sltJti)

    const metadata = sltContext.metadata || {}
    const rememberMe = metadata.rememberMe || false

    // Xóa đánh dấu xác thực lại cho thiết bị nếu có
    if (sltContext.purpose === TypeOfVerificationCode.LOGIN_UNTRUSTED_DEVICE_OTP && sltContext.metadata?.deviceId) {
      try {
        await this.tokenService.clearDeviceReverification(sltContext.userId, sltContext.metadata.deviceId)
        this.logger.debug(`Cleared device reverification for device ${sltContext.metadata.deviceId}`)
      } catch (error) {
        this.logger.error(`Failed to clear device reverification: ${error.message}`, error.stack)
        // Không throw lỗi ở đây để không ảnh hưởng đến luồng xác thực
      }
    }

    this.logger.debug(`[handleLoginVerification] Using rememberMe=${rememberMe}, 2FA verification status: not verified`)

    // Hoàn tất đăng nhập
    const loginResult = await this.coreService.finalizeLoginAfterVerification(
      sltContext.userId,
      sltContext.deviceId,
      rememberMe,
      res,
      ip,
      userAgent
    )

    this.logger.debug(`[handleLoginVerification] Login finalized successfully for user: ${sltContext.email}`)

    // Xóa SLT cookie
    this.cookieService.clearSltCookie(res)

    return {
      statusCode: HttpStatus.OK,
      message: this.i18nService.translate('auth.Auth.Otp.Verified'),
      data: loginResult
    }
  }

  /**
   * Xử lý xác minh thu hồi sessions cụ thể
   */
  private async handleRevokeSessionsVerification(
    sltContext: SltContextData & { sltJti: string },
    ip: string,
    userAgent: string
  ) {
    const { userId, metadata } = sltContext
    this.logger.debug(`[handleRevokeSessionsVerification] Processing for userId: ${userId}`)

    if (!metadata || (!metadata.sessionIds && !metadata.deviceIds)) {
      throw new Error('Không có thông tin sessions để thu hồi')
    }

    const options = {
      sessionIds: metadata.sessionIds,
      deviceIds: metadata.deviceIds,
      excludeCurrentSession: metadata.excludeCurrentSession ?? true
    }

    // Tạo active user để truyền vào service
    const activeUser = {
      userId,
      deviceId: sltContext.deviceId,
      sessionId: metadata.currentSessionId || '',
      email: sltContext.email
    } as AccessTokenPayload

    const result = await this.sessionsService.revokeItems(
      userId,
      options,
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
   * Xử lý xác minh thu hồi tất cả sessions
   */
  private async handleRevokeAllSessionsVerification(
    sltContext: SltContextData & { sltJti: string },
    ip: string,
    userAgent: string
  ) {
    const { userId, metadata } = sltContext
    this.logger.debug(`[handleRevokeAllSessionsVerification] Processing for userId: ${userId}`)

    if (!metadata) {
      throw new Error('Không có thông tin để thu hồi')
    }

    const options = {
      revokeAllUserSessions: true,
      excludeCurrentSession: metadata.excludeCurrentSession ?? true
    }

    // Tạo active user để truyền vào service
    const activeUser = {
      userId,
      deviceId: sltContext.deviceId,
      sessionId: metadata.currentSessionId || '',
      email: sltContext.email
    } as AccessTokenPayload

    const result = await this.sessionsService.revokeItems(
      userId,
      options,
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
   * Resend OTP
   */
  @IsPublic()
  @Post('resend')
  @HttpCode(HttpStatus.OK)
  async resendOtp(
    @Ip() ip: string,
    @UserAgent() userAgent: string,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response
  ): Promise<SendOtpResponseDto> {
    // Lấy SLT token từ cookie
    const sltCookieValue = req.cookies?.[CookieNames.SLT_TOKEN]
    if (!sltCookieValue) {
      throw AuthError.SLTCookieMissing()
    }

    // Lấy context từ SLT
    const sltContext = await this.otpService.validateSltFromCookieAndGetContext(sltCookieValue, ip, userAgent)

    // Gửi lại OTP
    const { email, purpose } = sltContext

    if (!email) {
      throw new Error('Email not found in SLT context')
    }

    // Khởi tạo OTP mới với SLT cookie
    const newSltJwt = await this.otpService.initiateOtpWithSltCookie({
      email,
      userId: sltContext.userId,
      deviceId: sltContext.deviceId,
      ipAddress: ip,
      userAgent,
      purpose,
      metadata: sltContext.metadata
    })

    // Set SLT cookie mới
    this.cookieService.setSltCookie(res, newSltJwt, purpose)

    return {
      message: await this.i18nService.translate('Auth.Otp.SentSuccessfully')
    }
  }
}
