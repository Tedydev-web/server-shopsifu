import { Controller, Post, Body, HttpCode, HttpStatus, Req, Res, Ip, Logger } from '@nestjs/common'
import { Request, Response } from 'express'
import { ZodSerializerDto } from 'nestjs-zod'
import { I18nService } from 'nestjs-i18n'
import { UseZodSchemas } from 'src/shared/decorators/use-zod-schema.decorator'

import { OtpService } from './otp.service'
import { CookieService } from 'src/routes/auth/shared/cookie/cookie.service'
import { UserAgent } from 'src/shared/decorators/user-agent.decorator'
import {
  SendOtpDto,
  SendOtpResponseDto,
  VerifyOtpDto,
  VerifyOtpResponseDto,
  VerifyOtpWithRedirectDto,
  VerifyOtpSuccessResponseDto,
  VerifyOtpSuccessResponseSchema,
  VerifyOtpResponseSchema
} from './dto/otp.dto'
import { CookieNames } from 'src/shared/constants/auth.constant'
import { AuthError } from 'src/routes/auth/auth.error'
import { IsPublic } from 'src/routes/auth/decorators/auth.decorator'
import { CoreService } from '../core/core.service'
import { TypeOfVerificationCode } from 'src/routes/auth/constants/auth.constants'

@Controller('auth/otp')
export class OtpController {
  private readonly logger = new Logger(OtpController.name)

  constructor(
    private readonly otpService: OtpService,
    private readonly cookieService: CookieService,
    private readonly i18nService: I18nService,
    private readonly coreService: CoreService
  ) {}

  /**
   * Gửi OTP
   */
  @IsPublic()
  @Post('send')
  @HttpCode(HttpStatus.OK)
  @ZodSerializerDto(SendOtpResponseDto)
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
  @ZodSerializerDto(VerifyOtpResponseDto)
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

      // Kiểm tra loại xác minh OTP
      if (sltContext.purpose === TypeOfVerificationCode.LOGIN_UNTRUSTED_DEVICE_OTP) {
        this.logger.debug(`[verifyOtp] Finalizing login after device verification for user ID: ${sltContext.userId}`)

        try {
          // Lấy trạng thái rememberMe từ metadata hoặc từ request body
          const rememberMe =
            sltContext.metadata && typeof sltContext.metadata === 'object' && 'rememberMe' in sltContext.metadata
              ? !!sltContext.metadata.rememberMe
              : !!body.rememberMe

          // Kiểm tra xem người dùng đã được xác thực 2FA chưa
          const twoFactorVerified =
            sltContext.metadata &&
            typeof sltContext.metadata === 'object' &&
            'twoFactorVerified' in sltContext.metadata &&
            !!sltContext.metadata.twoFactorVerified

          this.logger.debug(
            `[verifyOtp] Using rememberMe=${rememberMe} from ${sltContext.metadata && typeof sltContext.metadata === 'object' && 'rememberMe' in sltContext.metadata ? 'metadata' : 'request body'}`
          )
          this.logger.debug(`[verifyOtp] 2FA verification status: ${twoFactorVerified ? 'verified' : 'not verified'}`)

          // Hoàn tất đăng nhập sau khi xác minh thiết bị thành công
          const userInfo = await this.coreService.finalizeLoginAfterVerification(
            sltContext.userId,
            sltContext.deviceId,
            rememberMe,
            res,
            ip,
            userAgent
          )

          this.logger.debug(`[verifyOtp] Login finalized successfully for user: ${userInfo.email}`)

          // Xóa SLT cookie vì đã hoàn tất quá trình xác minh
          this.cookieService.clearSltCookie(res)

          // Sử dụng return hàm và sau đó không chạy thêm code nữa
          return {
            statusCode: HttpStatus.OK,
            message: await this.i18nService.translate('Auth.Otp.Verified'),
            data: {
              id: userInfo.id,
              email: userInfo.email,
              role: userInfo.roleName,
              isDeviceTrustedInSession: userInfo.isDeviceTrustedInSession,
              userProfile: userInfo.userProfile
            }
          }
        } catch (innerError) {
          this.logger.error(
            `[verifyOtp] Error in finalizeLoginAfterVerification: ${innerError.message}`,
            innerError.stack
          )
          throw innerError
        }
      }

      // Trả về thông báo xác minh thành công cho các loại OTP khác
      return {
        message: await this.i18nService.translate('Auth.Otp.Verified')
      }
    } catch (error) {
      this.logger.error(`[verifyOtp] Error processing OTP verification: ${error.message}`, error.stack)
      throw error
    }
  }

  /**
   * Resend OTP
   */
  @IsPublic()
  @Post('resend')
  @HttpCode(HttpStatus.OK)
  @ZodSerializerDto(SendOtpResponseDto)
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
