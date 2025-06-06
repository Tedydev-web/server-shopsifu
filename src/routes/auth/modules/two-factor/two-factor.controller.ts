import { Controller, Post, Body, HttpCode, HttpStatus, Req, Res, Ip, Inject, forwardRef, Logger } from '@nestjs/common'
import { Request, Response } from 'express'
import { TwoFactorService } from './two-factor.service'
import { UserAgent } from 'src/shared/decorators/user-agent.decorator'
import { ActiveUser } from 'src/routes/auth/shared/decorators/active-user.decorator'
import { AccessTokenPayload } from 'src/routes/auth/shared/auth.types'
import { TwoFactorVerifyDto, TwoFactorSetupDataDto, VerificationNeededResponseDto } from './two-factor.dto'
import { CookieNames, TypeOfVerificationCode } from 'src/routes/auth/shared/constants/auth.constants'
import { AuthError } from '../../auth.error'
import { IsPublic, Auth } from 'src/routes/auth/shared/decorators/auth.decorator'
import { AuthVerificationService } from '../../services/auth-verification.service'

@Auth()
@Controller('auth/2fa')
export class TwoFactorController {
  private readonly logger = new Logger(TwoFactorController.name)

  constructor(
    private readonly twoFactorService: TwoFactorService,
    @Inject(forwardRef(() => AuthVerificationService))
    private readonly authVerificationService: AuthVerificationService
  ) {}

  /**
   * Bắt đầu quá trình thiết lập 2FA.
   * Trả về secret và QR code URI để người dùng quét.
   * Khởi tạo một SLT để theo dõi quá trình xác nhận.
   */
  @Post('setup')
  @HttpCode(HttpStatus.OK)
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

    const { secret, uri } = await this.twoFactorService.generateSetupDetails(activeUser.userId)

    const verificationResult = await this.authVerificationService.initiateVerification(
      {
        userId: activeUser.userId,
        deviceId: activeUser.deviceId,
        email: activeUser.email,
        ipAddress: ip,
        userAgent: userAgent,
        purpose: TypeOfVerificationCode.SETUP_2FA,
        metadata: { secret }
      },
      res
    )

    return {
      message: verificationResult.message,
      data: { secret, uri }
    }
  }

  /**
   * Xác nhận thiết lập 2FA bằng cách gửi mã TOTP.
   * Endpoint này sử dụng `verifyCode` của service trung tâm.
   */
  @Post('confirm-setup')
  @HttpCode(HttpStatus.OK)
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

    return this.authVerificationService.verifyCode(sltCookieValue, body.code, ip, userAgent, res)
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
    return this.authVerificationService.verifyCode(sltCookieValue, body.code, ip, userAgent, res, {
      rememberMe: body.rememberMe
    })
  }

  /**
   * Bắt đầu quá trình vô hiệu hóa 2FA.
   * Cần xác thực bổ sung.
   */
  @Post('disable')
  @HttpCode(HttpStatus.OK)
  async disableTwoFactor(
    @ActiveUser() activeUser: AccessTokenPayload,
    @Ip() ip: string,
    @UserAgent() userAgent: string,
    @Res({ passthrough: true }) res: Response
  ): Promise<{ message: string; data: VerificationNeededResponseDto }> {
    this.logger.log(`[disableTwoFactor] Initiating 2FA disable for user: ${activeUser.userId}`)
    if (!activeUser.email) {
      throw AuthError.InternalServerError('Email not found in access token payload.')
    }
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
      message: verificationResult.message,
      data: {
        requiresAdditionalVerification: true,
        verificationType: verificationResult.verificationType
      }
    }
  }

  /**
   * Bắt đầu quá trình tạo lại mã khôi phục.
   * Cần xác thực bổ sung.
   */
  @Post('regenerate-recovery-codes')
  @HttpCode(HttpStatus.OK)
  async regenerateRecoveryCodes(
    @ActiveUser() activeUser: AccessTokenPayload,
    @Ip() ip: string,
    @UserAgent() userAgent: string,
    @Res({ passthrough: true }) res: Response
  ): Promise<{ message: string; data: VerificationNeededResponseDto }> {
    this.logger.log(`[regenerateRecoveryCodes] Initiating recovery code regeneration for user: ${activeUser.userId}`)
    if (!activeUser.email) {
      throw AuthError.InternalServerError('Email not found in access token payload.')
    }
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
      message: result.message,
      data: {
        requiresAdditionalVerification: true,
        verificationType: result.verificationType
      }
    }
  }
}
