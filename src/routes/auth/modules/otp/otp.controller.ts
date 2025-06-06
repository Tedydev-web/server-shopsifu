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
import { Throttle } from '@nestjs/throttler'
import { Request, Response } from 'express'
import { OtpService } from './otp.service'
import { I18nService } from 'nestjs-i18n'
import { AuthError } from '../../auth.error'
import { UserAgent } from 'src/shared/decorators/user-agent.decorator'
import { SendOtpDto, VerifyOtpDto, SendOtpResponseDto } from './otp.dto'
import { CoreService } from '../core/core.service'
import { CookieNames } from 'src/routes/auth/shared/constants/auth.constants'
import { SessionsService } from '../sessions/sessions.service'
import { IsPublic, Auth } from 'src/routes/auth/shared/decorators/auth.decorator'
import { ICookieService, ITokenService } from 'src/routes/auth/shared/auth.types'
import { COOKIE_SERVICE, REDIS_SERVICE, SLT_SERVICE, TOKEN_SERVICE } from 'src/shared/constants/injection.tokens'
import { I18nTranslations } from 'src/generated/i18n.generated'
import { RedisService } from 'src/providers/redis/redis.service'
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
  @Throttle({ default: { limit: 3, ttl: 60000 } })
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
      // Tìm người dùng để lấy ID. Service sẽ xử lý lỗi nếu không tìm thấy.
      const user = await this.coreService.findUserByEmail(body.email)
      if (!user) {
        // Vẫn nên giữ lại kiểm tra này để đưa ra lỗi sớm, tránh gọi service không cần thiết
        throw AuthError.EmailNotFound()
      }

      // Ủy quyền hoàn toàn cho AuthVerificationService
      const verificationResult = await this.authVerificationService.initiateVerification(
        {
          userId: user.id,
          deviceId: body.deviceId || 0, // Cung cấp giá trị mặc định nếu cần
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
      if (error instanceof HttpException) {
        throw error
      }
      throw AuthError.InternalServerError(error.message)
    }
  }

  /**
   * Xác minh OTP
   */
  @Throttle({ default: { limit: 5, ttl: 60000 } })
  @Post('verify')
  async verifyOtp(
    @Body() body: VerifyOtpDto,
    @Ip() ip: string,
    @UserAgent() userAgent: string,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response
  ): Promise<any> {
    this.logger.log(`[verifyOtp] Verifying OTP for purpose: ${body.purpose}`)

    // Get SLT cookie
    const sltCookieValue = req.cookies[CookieNames.SLT_TOKEN]
    if (!sltCookieValue) {
      throw AuthError.SLTCookieMissing()
    }

    // AuthVerificationService sẽ tự động xử lý việc xóa cookie
    return this.authVerificationService.verifyCode(sltCookieValue, body.code, ip, userAgent, res)
  }

  /**
   * Gửi lại OTP
   */
  @Throttle({ default: { limit: 3, ttl: 60000 } })
  @IsPublic()
  @Post('resend')
  @HttpCode(HttpStatus.OK)
  async resendOtp(
    @Ip() ip: string,
    @UserAgent() userAgent: string,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response
  ): Promise<SendOtpResponseDto> {
    const sltCookieValue = req.cookies[CookieNames.SLT_TOKEN]
    if (!sltCookieValue) {
      throw AuthError.SLTCookieMissing()
    }

    try {
      const result = await this.authVerificationService.reInitiateVerification(sltCookieValue, ip, userAgent, res)
      return {
        message: result.message
      }
    } catch (error) {
      this.logger.error(`[resendOtp] Error resending OTP: ${error.message}`, error.stack)
      if (error instanceof HttpException) {
        throw error
      }
      throw AuthError.InternalServerError(error.message)
    }
  }
}
