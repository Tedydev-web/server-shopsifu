import { Controller, Post, Body, HttpCode, HttpStatus, Req, Res, Ip, UseGuards, Logger } from '@nestjs/common'
import { Request, Response } from 'express'
import { ZodSerializerDto } from 'nestjs-zod'
import { I18nService } from 'nestjs-i18n'

import { TwoFactorService } from './two-factor.service'
import { CookieService } from 'src/routes/auth/shared/cookie/cookie.service'
import { UserAgent } from 'src/shared/decorators/user-agent.decorator'
import { AccessTokenGuard } from 'src/routes/auth/guards/access-token.guard'
import { ActiveUser } from 'src/routes/auth/decorators/active-user.decorator'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'
import {
  TwoFactorSetupDto,
  TwoFactorSetupResponseDto,
  TwoFactorConfirmSetupDto,
  TwoFactorConfirmSetupResponseDto,
  TwoFactorVerifyDto,
  TwoFactorVerifyResponseDto,
  DisableTwoFactorDto,
  DisableTwoFactorResponseDto,
  RegenerateRecoveryCodesDto,
  RegenerateRecoveryCodesResponseDto
} from './dto/two-factor.dto'
import { CookieNames } from 'src/shared/constants/auth.constant'
import { AuthError } from 'src/routes/auth/auth.error'
import { IsPublic } from 'src/routes/auth/decorators/auth.decorator'

@Controller('auth/2fa')
export class TwoFactorController {
  private readonly logger = new Logger(TwoFactorController.name)

  constructor(
    private readonly twoFactorService: TwoFactorService,
    private readonly cookieService: CookieService,
    private readonly i18nService: I18nService
  ) {}

  /**
   * Thiết lập 2FA
   */
  @Post('setup')
  @UseGuards(AccessTokenGuard)
  @HttpCode(HttpStatus.OK)
  @ZodSerializerDto(TwoFactorSetupResponseDto)
  async setupTwoFactor(
    @ActiveUser() activeUser: AccessTokenPayload,
    @Ip() ip: string,
    @UserAgent() userAgent: string,
    @Res({ passthrough: true }) res: Response
  ): Promise<TwoFactorSetupResponseDto> {
    const result = await this.twoFactorService.setupTwoFactor(
      activeUser.userId,
      activeUser.deviceId,
      ip,
      userAgent,
      res
    )

    return result
  }

  /**
   * Xác nhận thiết lập 2FA
   */
  @Post('confirm-setup')
  @UseGuards(AccessTokenGuard)
  @HttpCode(HttpStatus.OK)
  @ZodSerializerDto(TwoFactorConfirmSetupResponseDto)
  async confirmTwoFactorSetup(
    @ActiveUser() activeUser: AccessTokenPayload,
    @Body() body: TwoFactorConfirmSetupDto,
    @Ip() ip: string,
    @UserAgent() userAgent: string,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response
  ): Promise<TwoFactorConfirmSetupResponseDto> {
    // Lấy SLT token từ cookie
    const sltCookieValue = req.cookies?.[CookieNames.SLT_TOKEN]
    if (!sltCookieValue) {
      throw AuthError.SLTCookieMissing()
    }

    const result = await this.twoFactorService.confirmTwoFactorSetup(
      activeUser.userId,
      sltCookieValue,
      body.totpCode,
      ip,
      userAgent,
      res
    )

    return result
  }

  /**
   * Xác minh 2FA
   */
  @IsPublic()
  @Post('verify')
  @HttpCode(HttpStatus.OK)
  @ZodSerializerDto(TwoFactorVerifyResponseDto)
  async verifyTwoFactor(
    @Body() body: TwoFactorVerifyDto,
    @Ip() ip: string,
    @UserAgent() userAgent: string,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response
  ): Promise<TwoFactorVerifyResponseDto> {
    // Lấy SLT token từ cookie
    const sltCookieValue = req.cookies?.[CookieNames.SLT_TOKEN]
    if (!sltCookieValue) {
      throw AuthError.SLTCookieMissing()
    }

    const result = await this.twoFactorService.verifyTwoFactor(
      body.code,
      body.rememberMe || false,
      sltCookieValue,
      ip,
      userAgent,
      res
    )

    return result
  }

  /**
   * Tắt 2FA
   */
  @Post('disable')
  @UseGuards(AccessTokenGuard)
  @HttpCode(HttpStatus.OK)
  @ZodSerializerDto(DisableTwoFactorResponseDto)
  async disableTwoFactor(
    @ActiveUser() activeUser: AccessTokenPayload,
    @Body() body: DisableTwoFactorDto,
    @Ip() ip: string,
    @UserAgent() userAgent: string,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response
  ): Promise<DisableTwoFactorResponseDto> {
    // Lấy SLT token từ cookie nếu có
    const sltCookieValue = req.cookies?.[CookieNames.SLT_TOKEN]

    const result = await this.twoFactorService.disableTwoFactor(
      activeUser.userId,
      body.code,
      body.method,
      ip,
      userAgent,
      sltCookieValue
    )

    // Xóa SLT cookie nếu có
    if (sltCookieValue) {
      this.cookieService.clearSltCookie(res)
    }

    return result
  }

  /**
   * Tạo lại mã khôi phục
   */
  @Post('regenerate-recovery-codes')
  @UseGuards(AccessTokenGuard)
  @HttpCode(HttpStatus.OK)
  @ZodSerializerDto(RegenerateRecoveryCodesResponseDto)
  async regenerateRecoveryCodes(
    @ActiveUser() activeUser: AccessTokenPayload,
    @Body() body: RegenerateRecoveryCodesDto,
    @Ip() ip: string,
    @UserAgent() userAgent: string
  ): Promise<RegenerateRecoveryCodesResponseDto> {
    const result = await this.twoFactorService.regenerateRecoveryCodes(activeUser.userId, body.code, ip, userAgent)

    return result
  }
}
