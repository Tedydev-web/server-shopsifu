import { Controller, Post, Body, HttpCode, HttpStatus, Req, Res, Ip, Logger } from '@nestjs/common'
import { Request, Response } from 'express'
import { ZodSerializerDto } from 'nestjs-zod'
import { I18nService } from 'nestjs-i18n'

import { OtpService } from './otp.service'
import { CookieService } from 'src/routes/auth/shared/cookie/cookie.service'
import { UserAgent } from 'src/shared/decorators/user-agent.decorator'
import {
  SendOtpDto,
  SendOtpResponseDto,
  VerifyOtpDto,
  VerifyOtpResponseDto,
  VerifyOtpWithRedirectDto
} from './dto/otp.dto'
import { CookieNames } from 'src/shared/constants/auth.constant'
import { AuthError } from 'src/routes/auth/auth.error'
import { IsPublic } from 'src/routes/auth/decorators/auth.decorator'

@Controller('auth/otp')
export class OtpController {
  private readonly logger = new Logger(OtpController.name)

  constructor(
    private readonly otpService: OtpService,
    private readonly cookieService: CookieService,
    private readonly i18nService: I18nService
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
  ): Promise<VerifyOtpResponseDto | VerifyOtpWithRedirectDto> {
    // Lấy SLT token từ cookie
    const sltCookieValue = req.cookies?.[CookieNames.SLT_TOKEN]
    if (!sltCookieValue) {
      throw AuthError.SLTCookieMissing()
    }

    // Xác minh OTP
    await this.otpService.verifySltOtpStage(sltCookieValue, body.code, ip, userAgent)

    return {
      message: await this.i18nService.translate('Auth.Otp.Verified')
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
