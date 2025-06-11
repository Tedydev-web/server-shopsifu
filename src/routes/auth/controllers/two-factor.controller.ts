import {
  Controller,
  Post,
  Body,
  HttpCode,
  HttpStatus,
  Req,
  Res,
  Ip,
  Inject,
  forwardRef,
  Logger,
  UseGuards
} from '@nestjs/common'
import { Request, Response } from 'express'
import { TwoFactorService } from '../services/two-factor.service'
import { TWO_FACTOR_SERVICE } from 'src/shared/constants/injection.tokens'
import { UserAgent } from 'src/shared/decorators/user-agent.decorator'
import { ActiveUser } from 'src/shared/decorators/active-user.decorator'
import { AccessTokenPayload } from 'src/routes/auth/auth.types'
import { TwoFactorVerifyDto } from '../dtos/two-factor.dto'
import { CookieNames, TypeOfVerificationCode } from 'src/routes/auth/auth.constants'
import { AuthError } from '../auth.error'
import { IsPublic, Auth } from 'src/shared/decorators/auth.decorator'
import { AuthVerificationService } from '../services/auth-verification.service'
import { I18nService } from 'nestjs-i18n'
import { I18nTranslations } from 'src/generated/i18n.generated'
import { PoliciesGuard } from 'src/shared/guards/policies.guard'
import { CheckPolicies } from 'src/shared/decorators/check-policies.decorator'
import { Action, AppAbility } from 'src/shared/providers/casl/casl-ability.factory'
import { ActiveUserData } from 'src/shared/types/active-user.type'

@Auth()
@Controller('auth/2fa')
export class TwoFactorController {
  private readonly logger = new Logger(TwoFactorController.name)

  constructor(
    @Inject(TWO_FACTOR_SERVICE) private readonly twoFactorService: TwoFactorService,
    @Inject(forwardRef(() => AuthVerificationService))
    private readonly authVerificationService: AuthVerificationService,
    private readonly i18nService: I18nService<I18nTranslations>
  ) {}

  @Post('setup')
  @UseGuards(PoliciesGuard)
  @CheckPolicies((ability: AppAbility) => ability.can(Action.Update, 'UserProfile'))
  @HttpCode(HttpStatus.OK)
  async setupTwoFactor(
    @ActiveUser() activeUser: ActiveUserData,
    @Ip() ip: string,
    @UserAgent() userAgent: string,
    @Res({ passthrough: true }) res: Response
  ): Promise<any> {
    this.logger.log(`[setupTwoFactor] Initiating 2FA setup for user: ${activeUser.id}`)
    if (!activeUser.email) {
      throw AuthError.InternalServerError('Email not found in access token payload.')
    }

    const setupResult = await this.twoFactorService.generateSetupDetails(activeUser.id)

    const verificationResult = await this.authVerificationService.initiateVerification(
      {
        userId: activeUser.id,
        deviceId: activeUser.deviceId,
        email: activeUser.email,
        ipAddress: ip,
        userAgent: userAgent,
        purpose: TypeOfVerificationCode.SETUP_2FA,
        metadata: { twoFactorSecret: setupResult.data.secret }
      },
      res
    )

    return {
      message: verificationResult.message,
      data: {
        secret: setupResult.data.secret,
        qrCode: setupResult.data.qrCode
      }
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

    return this.authVerificationService.verifyCode(sltCookieValue, body.code, ip, userAgent, res, {
      twoFactorMethod: body.method || 'TOTP'
    })
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
    this.logger.debug(`[verifyTwoFactor] Verifying 2FA code with method: ${body.method}`)
    const sltCookieValue = req.cookies[CookieNames.SLT_TOKEN]
    if (!sltCookieValue) {
      throw AuthError.SLTCookieMissing()
    }
    // Truyền thêm method vào metadata để service trung tâm biết cách xác thực
    return this.authVerificationService.verifyCode(sltCookieValue, body.code, ip, userAgent, res, {
      twoFactorMethod: body.method || 'TOTP'
    })
  }

  /**
   * Bắt đầu quá trình vô hiệu hóa 2FA.
   * Cần xác thực bổ sung.
   */
  @Post('disable')
  @UseGuards(PoliciesGuard)
  @CheckPolicies((ability: AppAbility) => ability.can(Action.Update, 'UserProfile'))
  @HttpCode(HttpStatus.OK)
  async disableTwoFactor(
    @ActiveUser() activeUser: ActiveUserData,
    @Body() body: TwoFactorVerifyDto
  ): Promise<{ message: string }> {
    this.logger.log(`[disableTwoFactor] Attempting to disable 2FA for user: ${activeUser.id}`)
    return this.twoFactorService.disableVerification(activeUser.id, body.code, body.method)
  }

  /**
   * Tạo lại mã khôi phục.
   * Yêu cầu xác thực bằng TOTP hoặc một mã khôi phục cũ.
   */
  @Post('regenerate-recovery-codes')
  @UseGuards(PoliciesGuard)
  @CheckPolicies((ability: AppAbility) => ability.can(Action.Update, 'UserProfile'))
  @HttpCode(HttpStatus.OK)
  async regenerateRecoveryCodes(
    @ActiveUser() activeUser: ActiveUserData,
    @Body() body: TwoFactorVerifyDto,
    @Ip() ip: string,
    @UserAgent() userAgent: string
  ): Promise<{ message: string; data: { recoveryCodes: string[] } }> {
    this.logger.log(`[regenerateRecoveryCodes] User ${activeUser.id} is attempting to regenerate recovery codes.`)

    return this.twoFactorService.regenerateRecoveryCodes(activeUser.id, body.code, body.method, ip, userAgent)
  }
}
