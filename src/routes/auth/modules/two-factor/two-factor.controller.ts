import {
  Controller,
  Post,
  Body,
  HttpCode,
  HttpStatus,
  Req,
  Res,
  Ip,
  HttpException,
  Inject,
  forwardRef,
  Logger
} from '@nestjs/common'
import { Request, Response } from 'express'
import { I18nService } from 'nestjs-i18n'
import { I18nTranslations, I18nPath } from 'src/generated/i18n.generated'
import { ZodSerializerDto } from 'nestjs-zod'

import { TwoFactorService } from './two-factor.service'
import { UserAgent } from 'src/shared/decorators/user-agent.decorator'
import { ActiveUser } from 'src/routes/auth/shared/decorators/active-user.decorator'
import { AccessTokenPayload, ICookieService } from 'src/routes/auth/shared/auth.types'
import {
  TwoFactorVerifyDto,
  DisableTwoFactorDto,
  RegenerateRecoveryCodesDto,
  TwoFactorSetupResponseDto,
  TwoFactorConfirmSetupResponseDto,
  DisableTwoFactorResponseDto,
  RegenerateRecoveryCodesResponseDto
} from './two-factor.dto'
import { CookieNames, TypeOfVerificationCode } from 'src/routes/auth/shared/constants/auth.constants'
import { AuthError } from '../../auth.error'
import { IsPublic, Auth } from 'src/routes/auth/shared/decorators/auth.decorator'
import { COOKIE_SERVICE } from 'src/shared/constants/injection.tokens'
import { AuthVerificationService } from '../../services/auth-verification.service'

@Auth() // Requires authentication by default
@Controller('auth/2fa')
export class TwoFactorController {
  private readonly logger = new Logger(TwoFactorController.name)

  constructor(
    private readonly twoFactorService: TwoFactorService,
    @Inject(forwardRef(() => AuthVerificationService))
    private readonly authVerificationService: AuthVerificationService,
    @Inject(COOKIE_SERVICE) private readonly cookieService: ICookieService,
    private readonly i18nService: I18nService<I18nTranslations>
  ) {}

  /**
   * Bắt đầu quá trình thiết lập 2FA.
   * Trả về secret và QR code URI để người dùng quét.
   * Khởi tạo một SLT để theo dõi quá trình xác nhận.
   */
  @Post('setup')
  @HttpCode(HttpStatus.OK)
  @ZodSerializerDto(TwoFactorSetupResponseDto)
  async setupTwoFactor(
    @ActiveUser() activeUser: AccessTokenPayload,
    @Ip() ip: string,
    @UserAgent() userAgent: string,
    @Res({ passthrough: true }) res: Response
  ): Promise<any> {
    this.logger.log(`[setupTwoFactor] Initiating 2FA setup for user: ${activeUser.userId}`)

    if (!activeUser.email) {
      throw AuthError.InternalServerError('Email not found in access token payload.')
    }

    try {
      // 1. Lấy secret và uri từ service (không có side effect)
      const { secret, uri } = await this.twoFactorService.generateSetupDetails(activeUser.userId)

      // 2. Dùng AuthVerificationService để khởi tạo luồng xác thực và tạo SLT
      await this.authVerificationService.initiateVerification(
        {
          userId: activeUser.userId,
          deviceId: activeUser.deviceId,
          email: activeUser.email,
          ipAddress: ip,
          userAgent: userAgent,
          purpose: TypeOfVerificationCode.SETUP_2FA,
          metadata: { secret } // Truyền secret vào metadata để lưu trong SLT context
        },
        res
      )

      // 3. Trả về secret và uri cho client
      return {
        success: true,
        message: this.i18nService.t('auth.Auth.2FA.Setup.Success' as I18nPath),
        secret,
        uri
      }
    } catch (error) {
      this.handleError(error, 'setupTwoFactor')
    }
  }

  /**
   * Xác nhận thiết lập 2FA bằng cách gửi mã TOTP.
   * Endpoint này sử dụng `verifyCode` của service trung tâm.
   */
  @Post('confirm-setup')
  @HttpCode(HttpStatus.OK)
  @ZodSerializerDto(TwoFactorConfirmSetupResponseDto)
  async confirmTwoFactorSetup(
    @Body() body: TwoFactorVerifyDto,
    @Ip() ip: string,
    @UserAgent() userAgent: string,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response
  ): Promise<any> {
    this.logger.log(`[confirmTwoFactorSetup] Confirming 2FA setup.`)

    const sltCookieValue = req.cookies[CookieNames.SLT_TOKEN]
    if (!sltCookieValue) {
      throw AuthError.SLTCookieMissing()
    }

    try {
      // verifyCode sẽ xử lý tất cả: xác thực mã, sau đó gọi handlePostVerificationActions
      // trong đó có case SETUP_2FA sẽ gọi twoFactorService.confirmTwoFactorSetup
      const result = await this.authVerificationService.verifyCode(sltCookieValue, body.code, ip, userAgent, res)
      return result
    } catch (error) {
      this.handleError(error, 'confirmTwoFactorSetup', res)
    }
  }

  /**
   * Xác minh mã 2FA cho các hành động khác (đăng nhập, thu hồi session, etc.).
   * Đây là một endpoint chung sử dụng SLT.
   */
  @Post('verify')
  @IsPublic() // Endpoint này có thể được gọi bởi người dùng chưa đăng nhập (luồng login)
  async verifyTwoFactor(
    @Body() body: TwoFactorVerifyDto,
    @Ip() ip: string,
    @UserAgent() userAgent: string,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response
  ): Promise<any> {
    this.logger.debug(`[verifyTwoFactor] Verifying 2FA code`)
    const sltCookieValue = req.cookies[CookieNames.SLT_TOKEN]
    if (!sltCookieValue) {
      throw AuthError.SLTCookieMissing()
    }

    try {
      const verificationResult = await this.authVerificationService.verifyCode(
        sltCookieValue,
        body.code,
        ip,
        userAgent,
        res,
        { rememberMe: body.rememberMe } // Truyền rememberMe vào metadata
      )

      return verificationResult
    } catch (error) {
      this.handleError(error, 'verifyTwoFactor', res)
    }
  }

  /**
   * Bắt đầu quá trình vô hiệu hóa 2FA.
   * Cần xác thực bổ sung.
   */
  @Post('disable')
  @HttpCode(HttpStatus.OK)
  @ZodSerializerDto(DisableTwoFactorResponseDto)
  async disableTwoFactor(
    @ActiveUser() activeUser: AccessTokenPayload,
    @Ip() ip: string,
    @UserAgent() userAgent: string,
    @Res({ passthrough: true }) res: Response
  ): Promise<any> {
    this.logger.log(`[disableTwoFactor] Initiating 2FA disable for user: ${activeUser.userId}`)

    if (!activeUser.email) {
      throw AuthError.InternalServerError('Email not found in access token payload.')
    }

    try {
      // Khởi tạo luồng xác thực để vô hiệu hóa 2FA.
      // Service sẽ quyết định gửi OTP hay yêu cầu mã 2FA hiện tại.
      const verificationResult = await this.authVerificationService.initiateVerification(
        {
          userId: activeUser.userId,
          deviceId: activeUser.deviceId,
          email: activeUser.email,
          ipAddress: ip,
          userAgent: userAgent,
          purpose: TypeOfVerificationCode.DISABLE_2FA
        },
        res
      )

      return {
        success: true,
        message: verificationResult.message,
        verificationType: verificationResult.verificationType
      }
    } catch (error) {
      this.handleError(error, 'disableTwoFactor')
    }
  }

  /**
   * Bắt đầu quá trình tạo lại mã khôi phục.
   * Cần xác thực bổ sung.
   */
  @Post('regenerate-recovery-codes')
  @HttpCode(HttpStatus.OK)
  @ZodSerializerDto(RegenerateRecoveryCodesResponseDto)
  async regenerateRecoveryCodes(
    @ActiveUser() activeUser: AccessTokenPayload,
    @Ip() ip: string,
    @UserAgent() userAgent: string,
    @Res({ passthrough: true }) res: Response
  ): Promise<any> {
    this.logger.log(`[regenerateRecoveryCodes] Initiating recovery code regeneration for user: ${activeUser.userId}`)

    if (!activeUser.email) {
      throw AuthError.InternalServerError('Email not found in access token payload.')
    }

    try {
      // Đây là hành động nhạy cảm, cần xác thực.
      const result = await this.authVerificationService.initiateVerification(
        {
          userId: activeUser.userId,
          deviceId: activeUser.deviceId,
          email: activeUser.email,
          ipAddress: ip,
          userAgent: userAgent,
          purpose: TypeOfVerificationCode.REGENERATE_2FA_CODES
        },
        res
      )

      return {
        success: true,
        message: result.message,
        verificationType: result.verificationType
      }
    } catch (error) {
      this.handleError(error, 'regenerateRecoveryCodes')
    }
  }

  private handleError(error: Error, method: string, res?: Response) {
    this.logger.error(`[${method}] Error: ${error.message}`, error.stack)

    // Clear SLT cookie in case of error, if response object is available
    if (res) {
      this.cookieService.clearSltCookie(res)
    }

    if (error instanceof HttpException) {
      throw error
    }

    throw AuthError.InternalServerError(error.message)
  }
}
