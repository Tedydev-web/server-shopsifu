import { Controller, Post, Body, Req, Res, HttpStatus, HttpCode, Logger, Ip, Inject, forwardRef } from '@nestjs/common'
import { Throttle } from '@nestjs/throttler'
import { Request, Response } from 'express'
import { AuthError } from '../auth.error'
import { UserAgent } from 'src/shared/decorators/user-agent.decorator'
import { SendOtpDto, VerifyOtpDto } from '../dtos/otp.dto'
import { CoreService } from '../services/core.service'
import { CookieNames, TypeOfVerificationCode, TypeOfVerificationCodeType } from 'src/routes/auth/auth.constants'
import { IsPublic } from 'src/shared/decorators/auth.decorator'
import { AuthVerificationService } from '../services/auth-verification.service'
import { I18nService } from 'nestjs-i18n'
import { I18nTranslations } from 'src/generated/i18n.generated'

@Controller('auth/otp')
export class OtpController {
  private readonly logger = new Logger(OtpController.name)

  constructor(
    @Inject(forwardRef(() => AuthVerificationService))
    private readonly authVerificationService: AuthVerificationService,
    private readonly coreService: CoreService,
    private readonly i18nService: I18nService<I18nTranslations>
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
  ): Promise<any> {
    const user = await this.coreService.findUserByEmail(body.email)

    if (!user) {
      const sensitivePurposes: TypeOfVerificationCodeType[] = [
        TypeOfVerificationCode.LOGIN,
        TypeOfVerificationCode.RESET_PASSWORD
      ]
      if (sensitivePurposes.includes(body.purpose)) {
        return {
          message: 'auth.success.otp.sent',
          verificationType: 'OTP'
        }
      }
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

    return {
      message: verificationResult.message,
      ...verificationResult
    }
  }

  @Throttle({ default: { limit: 6, ttl: 60000 } })
  @IsPublic()
  @Post('verify')
  async verifyOtp(
    @Body() body: VerifyOtpDto,
    @Ip() ip: string,
    @UserAgent() userAgent: string,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response
  ): Promise<any> {
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
  ): Promise<any> {
    const sltCookieValue = req.cookies[CookieNames.SLT_TOKEN]
    if (!sltCookieValue) {
      throw AuthError.SLTCookieMissing()
    }

    return this.authVerificationService.reInitiateVerification(sltCookieValue, ip, userAgent, res)
  }
}
