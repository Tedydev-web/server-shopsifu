import { Controller, Post, Body, HttpCode, HttpStatus, Req, Res, Ip, Inject, forwardRef, Logger } from '@nestjs/common'
import { Request, Response } from 'express'
import { TwoFactorService } from './two-factor.service'
import { TWO_FACTOR_SERVICE } from 'src/shared/constants/injection.tokens'
import { UserAgent } from 'src/shared/decorators/user-agent.decorator'
import { ActiveUser } from 'src/routes/auth/shared/decorators/active-user.decorator'
import { AccessTokenPayload } from 'src/routes/auth/shared/auth.types'
import { TwoFactorVerifyDto, TwoFactorSetupDataDto, VerificationNeededResponseDto } from './two-factor.dto'
import { CookieNames, TypeOfVerificationCode } from 'src/routes/auth/shared/constants/auth.constants'
import { AuthError } from '../../auth.error'
import { IsPublic, Auth } from 'src/routes/auth/shared/decorators/auth.decorator'
import { AuthVerificationService } from '../../../../shared/services/auth-verification.service'

@Auth()
@Controller('auth/2fa')
export class TwoFactorController {
  private readonly logger = new Logger(TwoFactorController.name)

  constructor(
    @Inject(TWO_FACTOR_SERVICE) private readonly twoFactorService: TwoFactorService,
    @Inject(forwardRef(() => AuthVerificationService))
    private readonly authVerificationService: AuthVerificationService
  ) {}

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

    const { secret, qrCode } = await this.twoFactorService.generateSetupDetails(activeUser.userId)

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
      data: { secret, qrCode }
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
    return this.authVerificationService.verifyCode(sltCookieValue, body.code, ip, userAgent, res)
  }

  /**
   * Bắt đầu quá trình vô hiệu hóa 2FA.
   * Cần xác thực bổ sung.
   */
  @Post('disable')
  @HttpCode(HttpStatus.OK)
  async disableTwoFactor(
    @ActiveUser() activeUser: AccessTokenPayload,
    @Body() body: TwoFactorVerifyDto
  ): Promise<{ message: string }> {
    this.logger.log(`[disableTwoFactor] Attempting to disable 2FA for user: ${activeUser.userId}`)

    const isValid = await this.twoFactorService.verifyCode(body.code, {
      userId: activeUser.userId
    })

    if (!isValid) {
      throw AuthError.InvalidTOTP() // Hoặc một lỗi chung hơn cho mã không hợp lệ
    }

    await this.twoFactorService.disableVerification(activeUser.userId)

    return {
      message: 'auth.Auth.Error.2FA.Disable.Success'
    }
  }

  /**
   * Tạo lại mã khôi phục.
   * Yêu cầu xác thực bằng TOTP hoặc một mã khôi phục cũ.
   */
  @Post('regenerate-recovery-codes')
  @HttpCode(HttpStatus.OK)
  async regenerateRecoveryCodes(
    @ActiveUser() activeUser: AccessTokenPayload,
    @Body() body: TwoFactorVerifyDto,
    @Ip() ip: string,
    @UserAgent() userAgent: string
  ): Promise<{ message: string; data: { recoveryCodes: string[] } }> {
    this.logger.log(`[regenerateRecoveryCodes] User ${activeUser.userId} is attempting to regenerate recovery codes.`)

    // Xác thực người dùng bằng mã TOTP hoặc recovery code hiện tại
    const isValid = await this.twoFactorService.verifyCode(body.code, {
      userId: activeUser.userId
    })

    if (!isValid) {
      this.logger.warn(`[regenerateRecoveryCodes] Invalid 2FA code provided by user ${activeUser.userId}.`)
      throw AuthError.InvalidTOTP()
    }

    // Nếu mã hợp lệ, tạo mã khôi phục mới
    const recoveryCodes = await this.twoFactorService.regenerateRecoveryCodes(activeUser.userId, ip, userAgent)

    return {
      message: 'auth.Auth.Error.2FA.RecoveryCodesRegenerated',
      data: {
        recoveryCodes
      }
    }
  }
}
