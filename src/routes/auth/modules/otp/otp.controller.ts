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
  HttpException,
  BadRequestException
} from '@nestjs/common'
import { Request, Response } from 'express'
import { OtpService } from './otp.service'
import { I18nService } from 'nestjs-i18n'
import { AuthError } from '../../auth.error'
import { UserAgent } from 'src/shared/decorators/user-agent.decorator'
import { SendOtpDto, VerifyOtpDto, SendOtpResponseDto } from './otp.dto'
import { CoreService } from '../core/core.service'
import { TypeOfVerificationCode, TypeOfVerificationCodeType } from 'src/shared/constants/auth.constants'
import { SltContextData } from 'src/routes/auth/auth.types'
import { SessionsService } from '../sessions/sessions.service'
import { CookieNames } from 'src/shared/constants/auth.constants'
import { IsPublic, Auth } from 'src/shared/decorators/auth.decorator'
import { ICookieService, ITokenService } from 'src/routes/auth/shared/auth.types'
import { COOKIE_SERVICE, REDIS_SERVICE, SLT_SERVICE, TOKEN_SERVICE } from 'src/shared/constants/injection.tokens'
import { I18nTranslations, I18nPath } from 'src/generated/i18n.generated'
import { RedisService } from 'src/providers/redis/redis.service'
import { RedisKeyManager } from 'src/shared/utils/redis-keys.utils'
import { AuthVerificationService } from 'src/routes/auth/services/auth-verification.service'
import { SLTService } from 'src/routes/auth/shared/services/slt.service'

@IsPublic()
@Auth([])
@Controller('auth/otp')
export class OtpController {
  private readonly logger = new Logger(OtpController.name)

  constructor(
    private readonly otpService: OtpService,
    @Inject(forwardRef(() => AuthVerificationService))
    private readonly authVerificationService: AuthVerificationService,
    @Inject(COOKIE_SERVICE) private readonly cookieService: ICookieService,
    private readonly i18nService: I18nService<I18nTranslations>,
    private readonly coreService: CoreService,
    @Inject(forwardRef(() => SessionsService))
    private readonly sessionsService: SessionsService,
    @Inject(TOKEN_SERVICE) private readonly tokenService: ITokenService,
    @Inject(REDIS_SERVICE) private readonly redisService: RedisService,
    @Inject(SLT_SERVICE) private readonly sltService: SLTService
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
    this.logger.log(`[sendOtp] Sending OTP to: ${body.email}, purpose: ${body.purpose}`)

    try {
      // Kiểm tra user tồn tại
      const user = await this.coreService.findUserByEmail(body.email)
      if (!user) {
        throw AuthError.EmailNotFound()
      }

      // Khởi tạo xác thực thông qua AuthVerificationService
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
        message: verificationResult.message
      }
    } catch (error) {
      this.logger.error(`[sendOtp] Error sending OTP: ${error.message}`, error.stack)
      if (error instanceof AuthError) {
        throw error
      }
      throw AuthError.InternalServerError(error.message)
    }
  }

  /**
   * Xác minh OTP
   */
  @Post('verify')
  async verifyOtp(
    @Body() body: VerifyOtpDto,
    @Ip() ip: string,
    @UserAgent() userAgent: string,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response
  ): Promise<any> {
    this.logger.log(`[verifyOtp] Verifying OTP for purpose: ${body.purpose}`)

    try {
      // Get SLT cookie
      const sltCookieValue = req.cookies?.slt_token

      if (!sltCookieValue) {
        throw AuthError.SLTCookieMissing()
      }

      // Sử dụng AuthVerificationService để xác minh OTP
      const verificationResult = await this.authVerificationService.verifyCode(
        sltCookieValue,
        body.code,
        ip,
        userAgent,
        req,
        res
      )

      // Xóa cookie SLT sau khi xác minh
      this.cookieService.clearSltCookie(res)

      // Trả về kết quả thích hợp dựa trên purpose
      return {
        success: verificationResult.success,
        message: verificationResult.message,
        requiresDeviceVerification: verificationResult.requiresDeviceVerification,
        requiresAdditionalVerification: verificationResult.requiresAdditionalVerification,
        redirectUrl: verificationResult.redirectUrl,
        user: verificationResult.user
      }
    } catch (error) {
      this.logger.error(`[verifyOtp] Error: ${error.message}`, error.stack)

      // Clear SLT cookie in case of error
      this.cookieService.clearSltCookie(res)

      if (error instanceof AuthError) {
        throw error
      }

      throw AuthError.InternalServerError(error.message)
    }
  }

  /**
   * Gửi lại OTP
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
    try {
      // Lấy SLT cookie từ request
      const sltCookieValue = req.cookies?.slt_token

      if (!sltCookieValue) {
        throw AuthError.SLTCookieMissing()
      }

      // Xác thực SLT và lấy context
      const sltContext = await this.sltService.validateSltFromCookieAndGetContext(sltCookieValue, ip, userAgent)

      // Lấy thông tin email từ context
      const email = sltContext.email
      if (!email) {
        throw AuthError.EmailMissingInSltContext()
      }

      // Sử dụng AuthVerificationService để khởi tạo lại quá trình xác thực
      const verificationResult = await this.authVerificationService.initiateVerification(
        {
          userId: sltContext.userId,
          deviceId: sltContext.deviceId,
          email,
          ipAddress: ip,
          userAgent,
          purpose: sltContext.purpose,
          metadata: {
            ...sltContext.metadata,
            resent: true
          }
        },
        res
      )

      return {
        message: verificationResult.message || this.i18nService.t('auth.Auth.Otp.SentSuccessfully' as I18nPath)
      }
    } catch (error) {
      this.logger.error(`[resendOtp] Error resending OTP: ${error.message}`, error.stack)
      if (error instanceof AuthError) {
        throw error
      }
      throw AuthError.InternalServerError(error.message)
    }
  }
}
