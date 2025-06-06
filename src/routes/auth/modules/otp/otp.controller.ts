import { Controller, Post, Body, Req, Res, HttpStatus, HttpCode, Logger, Ip, Inject, forwardRef } from '@nestjs/common'
import { Throttle } from '@nestjs/throttler'
import { Request, Response } from 'express'
import { AuthError } from '../../auth.error'
import { UserAgent } from 'src/shared/decorators/user-agent.decorator'
import { SendOtpDto, VerifyOtpDto } from './otp.dto'
import { CoreService } from '../core/core.service'
import { CookieNames } from 'src/routes/auth/shared/constants/auth.constants'
import { IsPublic, Auth } from 'src/routes/auth/shared/decorators/auth.decorator'
import { AuthVerificationService } from 'src/routes/auth/services/auth-verification.service'

@Controller('auth/otp')
export class OtpController {
  private readonly logger = new Logger(OtpController.name)

  constructor(
    @Inject(forwardRef(() => AuthVerificationService))
    private readonly authVerificationService: AuthVerificationService,
    private readonly coreService: CoreService
  ) {}

  @Throttle({ default: { limit: 3, ttl: 60000 } })
  @IsPublic()
  @Post('send')
  @HttpCode(HttpStatus.OK)
  async sendOtp(
    @Body() body: SendOtpDto,
    @Ip() ip: string,
    @UserAgent() userAgent: string,
    @Res({ passthrough: true }) res: Response
  ): Promise<{ message: string; data: any }> {
    this.logger.log(`[sendOtp] Sending OTP to: ${body.email}, purpose: ${body.purpose}`)

    const user = await this.coreService.findUserByEmail(body.email)
    if (!user) {
      throw AuthError.EmailNotFound()
    }

    const verificationResult = await this.authVerificationService.initiateVerification(
      {
        userId: user.id,
        deviceId: body.deviceId || 0,
        email: body.email,
        ipAddress: ip,
        userAgent,
        purpose: body.purpose,
        metadata: body.metadata
      },
      res
    )

    // The interceptor will wrap this into the standard response format.
    // The `data` part contains any information the client might need, like a verification token (SLT).
    return {
      message: verificationResult.message,
      data: verificationResult.data
    }
  }

  @Throttle({ default: { limit: 5, ttl: 60000 } })
  @IsPublic()
  @Post('verify')
  async verifyOtp(
    @Body() body: VerifyOtpDto,
    @Ip() ip: string,
    @UserAgent() userAgent: string,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response
  ): Promise<any> {
    this.logger.log(`[verifyOtp] Verifying OTP.`)

    const sltCookieValue = req.cookies[CookieNames.SLT_TOKEN]
    if (!sltCookieValue) {
      throw AuthError.SLTCookieMissing()
    }

    return this.authVerificationService.verifyCode(sltCookieValue, body.code, ip, userAgent, res)
  }

  @Throttle({ default: { limit: 3, ttl: 60000 } })
  @IsPublic()
  @Post('resend')
  @HttpCode(HttpStatus.OK)
  async resendOtp(
    @Ip() ip: string,
    @UserAgent() userAgent: string,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response
  ): Promise<{ message: string; data: any }> {
    const sltCookieValue = req.cookies[CookieNames.SLT_TOKEN]
    if (!sltCookieValue) {
      throw AuthError.SLTCookieMissing()
    }

    const result = await this.authVerificationService.reInitiateVerification(sltCookieValue, ip, userAgent, res)

    return {
      message: result.message,
      data: result.data
    }
  }
}
