import {
  Controller,
  Post,
  Body,
  Req,
  Res,
  HttpStatus,
  HttpCode,
  Logger,
  Ip,
  Inject,
  forwardRef,
  HttpException
} from '@nestjs/common'
import { Request, Response } from 'express'
import { OtpService } from './otp.service'
import { I18nService } from 'nestjs-i18n'
import { AuthError } from '../../auth.error'
import { UserAgent } from 'src/shared/decorators/user-agent.decorator'
import { SendOtpDto, VerifyOtpDto, SendOtpResponseDto } from './otp.dto'
import { CoreService } from '../core/core.service'
import { TypeOfVerificationCode } from 'src/shared/constants/auth.constants'
import { SltContextData } from 'src/routes/auth/auth.types'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'
import { SessionsService } from '../sessions/sessions.service'
import { CookieNames } from 'src/shared/constants/auth.constants'
import { IsPublic } from 'src/shared/decorators/auth.decorator'
import { ICookieService, ITokenService } from 'src/shared/types/auth.types'
import { COOKIE_SERVICE, TOKEN_SERVICE } from 'src/shared/constants/injection.tokens'
import { I18nTranslations, I18nPath } from 'src/generated/i18n.generated'

@Controller('auth/otp')
export class OtpController {
  private readonly logger = new Logger(OtpController.name)

  constructor(
    private readonly otpService: OtpService,
    @Inject(COOKIE_SERVICE) private readonly cookieService: ICookieService,
    private readonly i18nService: I18nService<I18nTranslations>,
    private readonly coreService: CoreService,
    @Inject(forwardRef(() => SessionsService))
    private readonly sessionsService: SessionsService,
    @Inject(TOKEN_SERVICE) private readonly tokenService: ITokenService
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
    this.logger.debug(`[sendOtp] Initiating OTP for email: ${email}, type: ${type}, IP: ${ip}`)
    try {
      // Khởi tạo OTP với SLT cookie
      const sltJwt = await this.otpService.initiateOtpWithSltCookie({
        email,
        userId: 0, // Được cập nhật sau khi tìm user
        deviceId: 0, // Được cập nhật sau khi tìm device
        ipAddress: ip,
        userAgent,
        purpose: type as TypeOfVerificationCode
      })

      // Set SLT cookie
      this.cookieService.setSltCookie(res, sltJwt, type as TypeOfVerificationCode)

      return {
        message: await this.i18nService.translate('Auth.Otp.SentSuccessfully' as I18nPath)
      }
    } catch (error) {
      this.logger.error(`[sendOtp] Error: ${error.message}`, error.stack)
      if (error instanceof HttpException) throw error
      throw AuthError.InternalServerError(error.message)
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
      this.logger.debug(`[verifyOtp] Verifying OTP with code: ${body.code}, IP: ${ip}`)
      // Lấy SLT cookie từ request
      const sltCookieValue = req.cookies[CookieNames.SLT_TOKEN]
      if (!sltCookieValue) {
        throw AuthError.SLTCookieMissing()
      }

      // Xác minh OTP và SLT
      const sltContext = await this.otpService.verifySltOtpStage(sltCookieValue, body.code, ip, userAgent)

      // Xử lý dựa vào purpose trong SLT context
      const purpose = sltContext.purpose as unknown as TypeOfVerificationCode
      switch (purpose) {
        case TypeOfVerificationCode.LOGIN_UNTRUSTED_DEVICE_OTP:
          return await this.handleLoginVerification(sltContext, body, res, ip, userAgent)

        case TypeOfVerificationCode.REVOKE_SESSIONS:
          return await this.handleRevokeSessionsVerification(sltContext, ip, userAgent, res)

        case TypeOfVerificationCode.REVOKE_ALL_SESSIONS:
          return await this.handleRevokeAllSessionsVerification(sltContext, ip, userAgent, res)

        default:
          // Xóa SLT cookie vì đã hoàn tất quá trình xác minh
          this.cookieService.clearSltCookie(res)

          // Trả về thông báo xác minh thành công cho các loại OTP khác
          return {
            statusCode: HttpStatus.OK,
            message: await this.i18nService.translate('Auth.Otp.Verified' as I18nPath),
            data: { verified: true }
          }
      }
    } catch (error) {
      this.logger.error(`[verifyOtp] Error processing OTP verification: ${error.message}`, error.stack)
      if (error instanceof HttpException) throw error
      throw AuthError.InternalServerError(error.message)
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
    try {
      // Cập nhật SLT context để đánh dấu là đã hoàn thành
      await this.otpService.finalizeSlt(sltContext.sltJti)

      const metadata = sltContext.metadata || {}
      const rememberMe = metadata.rememberMe || false

      // Xóa đánh dấu xác thực lại cho thiết bị nếu có
      if (
        String(sltContext.purpose) === String(TypeOfVerificationCode.LOGIN_UNTRUSTED_DEVICE_OTP) &&
        sltContext.metadata?.deviceId
      ) {
        try {
          await this.tokenService.clearDeviceReverification(sltContext.userId, sltContext.metadata.deviceId)
          this.logger.debug(`Cleared device reverification for device ${sltContext.metadata.deviceId}`)
        } catch (error) {
          this.logger.error(`Failed to clear device reverification: ${error.message}`, error.stack)
          // Không throw lỗi ở đây để không ảnh hưởng đến luồng xác thực
        }
      }

      this.logger.debug(
        `[handleLoginVerification] Using rememberMe=${rememberMe}, 2FA verification status: not verified`
      )

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

      const message = loginResult.messageKey
        ? await this.i18nService.translate(loginResult.messageKey as I18nPath)
        : await this.i18nService.translate('Auth.Otp.Verified' as I18nPath)

      // Prepare user response with potentially picked UserProfile fields
      const userResponse = {
        ...loginResult.user,
        userProfile: loginResult.user.userProfile
          ? {
              username: loginResult.user.userProfile.username,
              avatar: loginResult.user.userProfile.avatar
            }
          : null
      }

      return {
        statusCode: HttpStatus.OK,
        message,
        data: { user: userResponse }
      }
    } catch (error) {
      this.logger.error(`[handleLoginVerification] Error: ${error.message}`, error.stack)
      if (error instanceof HttpException) throw error
      throw AuthError.InternalServerError(error.message)
    }
  }

  /**
   * Xử lý xác minh thu hồi sessions cụ thể
   */
  private async handleRevokeSessionsVerification(
    sltContext: SltContextData & { sltJti: string },
    ip: string,
    userAgent: string,
    res: Response
  ) {
    const { userId, metadata } = sltContext
    this.logger.debug(`[handleRevokeSessionsVerification] Processing for userId: ${userId}`)
    try {
      if (!metadata || (!metadata.sessionIds && !metadata.deviceIds)) {
        throw AuthError.InsufficientRevocationData()
      }

      const options = {
        sessionIds: metadata.sessionIds,
        deviceIds: metadata.deviceIds,
        excludeCurrentSession: metadata.excludeCurrentSession ?? true
      }

      const currentSessionDetails = {
        sessionId: metadata.currentSessionIdToExclude,
        deviceId: metadata.currentDeviceIdToExclude
      }

      const result = await this.sessionsService.revokeItems(
        userId,
        options,
        currentSessionDetails,
        undefined,
        undefined,
        ip,
        userAgent
      )

      this.cookieService.clearSltCookie(res)

      const translatedMessage = result.message
        ? await this.i18nService.translate(result.message as I18nPath)
        : 'Operation completed.' // Fallback message, should ideally not happen

      return {
        statusCode: HttpStatus.OK,
        message: translatedMessage,
        data: {
          revokedSessionsCount: result.revokedSessionsCount,
          untrustedDevicesCount: result.untrustedDevicesCount,
          revokedSessionIds: result.revokedSessionIds || [],
          revokedDeviceIds: result.revokedDeviceIds || [],
          requiresAdditionalVerification: false
        }
      }
    } catch (error) {
      this.logger.error(`[handleRevokeSessionsVerification] Error: ${error.message}`, error.stack)
      if (error instanceof HttpException) throw error
      throw AuthError.InternalServerError(error.message)
    }
  }

  /**
   * Xử lý xác minh thu hồi tất cả sessions
   */
  private async handleRevokeAllSessionsVerification(
    sltContext: SltContextData & { sltJti: string },
    ip: string,
    userAgent: string,
    res: Response
  ) {
    const { userId, metadata } = sltContext
    this.logger.debug(`[handleRevokeAllSessionsVerification] Processing for userId: ${userId}`)
    try {
      if (!metadata) {
        throw AuthError.InsufficientRevocationData()
      }

      const options = {
        revokeAllUserSessions: true,
        excludeCurrentSession: metadata.excludeCurrentSession ?? true
      }

      const currentSessionDetails = {
        sessionId: metadata.currentSessionIdToExclude,
        deviceId: metadata.currentDeviceIdToExclude
      }

      const result = await this.sessionsService.revokeItems(
        userId,
        options,
        currentSessionDetails,
        undefined,
        undefined,
        ip,
        userAgent
      )

      this.cookieService.clearSltCookie(res)

      const translatedMessage = result.message
        ? await this.i18nService.translate(result.message as I18nPath)
        : 'Operation completed.' // Fallback message, should ideally not happen

      return {
        statusCode: HttpStatus.OK,
        message: translatedMessage,
        data: {
          revokedSessionsCount: result.revokedSessionsCount,
          untrustedDevicesCount: result.untrustedDevicesCount,
          revokedSessionIds: result.revokedSessionIds || [],
          revokedDeviceIds: result.revokedDeviceIds || [],
          requiresAdditionalVerification: false
        }
      }
    } catch (error) {
      this.logger.error(`[handleRevokeAllSessionsVerification] Error: ${error.message}`, error.stack)
      if (error instanceof HttpException) throw error
      throw AuthError.InternalServerError(error.message)
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
    this.logger.debug(`[resendOtp] Resending OTP, IP: ${ip}`)
    try {
      const sltCookieValue = req.cookies[CookieNames.SLT_TOKEN]
      if (!sltCookieValue) {
        this.logger.warn('[resendOtp] SLT cookie missing for resend.')
        throw AuthError.SLTCookieMissing()
      }

      // Validate SLT and get context. We don't expect a specific purpose here, just that it's a valid SLT.
      const sltContext = await this.otpService.validateSltFromCookieAndGetContext(sltCookieValue, ip, userAgent)

      if (!sltContext.email || !sltContext.purpose) {
        this.logger.error('[resendOtp] Email or purpose missing in SLT context for resend.')
        throw AuthError.InternalServerError('Invalid SLT context for resend.')
      }

      // Re-initiate OTP with the same purpose and details from the SLT context
      const newSltJwt = await this.otpService.initiateOtpWithSltCookie({
        email: sltContext.email,
        userId: sltContext.userId,
        deviceId: sltContext.deviceId,
        ipAddress: ip, // Use current IP
        userAgent, // Use current userAgent
        purpose: sltContext.purpose as TypeOfVerificationCode, // Cast to TypeOfVerificationCode
        metadata: sltContext.metadata
      })

      // Set the new SLT cookie
      this.cookieService.setSltCookie(res, newSltJwt, sltContext.purpose as TypeOfVerificationCode)

      return {
        message: await this.i18nService.translate('Auth.Otp.SentSuccessfully' as I18nPath)
      }
    } catch (error) {
      this.logger.error(`[resendOtp] Error: ${error.message}`, error.stack)
      if (error instanceof HttpException) throw error
      throw AuthError.InternalServerError(error.message)
    }
  }
}
