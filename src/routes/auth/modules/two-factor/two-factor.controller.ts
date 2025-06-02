import {
  Controller,
  Post,
  Body,
  HttpCode,
  HttpStatus,
  Req,
  Res,
  Ip,
  UseGuards,
  Logger,
  InternalServerErrorException,
  HttpException
} from '@nestjs/common'
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
  async setupTwoFactor(
    @ActiveUser() activeUser: AccessTokenPayload,
    @Ip() ip: string,
    @UserAgent() userAgent: string,
    @Res({ passthrough: false }) res: Response
  ): Promise<void> {
    try {
      // Gọi service để thiết lập 2FA và trả về secret và URI
    const result = await this.twoFactorService.setupTwoFactor(
      activeUser.userId,
      activeUser.deviceId,
      ip,
      userAgent,
      res
    )

      this.logger.debug(
        `2FA setup initiated for user ${activeUser.userId} with result: ${JSON.stringify({
          secretLength: result.secret.length,
          uriLength: result.uri.length
        })}`
      )

      // Trả về response trực tiếp từ controller để tránh serialization pipeline của NestJS
      res.status(200).json({
        secret: result.secret,
        uri: result.uri
      })
    } catch (error) {
      this.logger.error(`Error in setupTwoFactor for user ${activeUser.userId}: ${error.message}`, error.stack)

      // Xử lý lỗi và trả về response thích hợp
      if (error instanceof HttpException) {
        throw error
      } else {
        throw new InternalServerErrorException('An error occurred during 2FA setup')
      }
    }
  }

  /**
   * Xác nhận thiết lập 2FA
   */
  @Post('confirm-setup')
  @UseGuards(AccessTokenGuard)
  @HttpCode(HttpStatus.OK)
  async confirmTwoFactorSetup(
    @ActiveUser() activeUser: AccessTokenPayload,
    @Body() body: TwoFactorConfirmSetupDto,
    @Ip() ip: string,
    @UserAgent() userAgent: string,
    @Req() req: Request,
    @Res({ passthrough: false }) res: Response
  ): Promise<void> {
    try {
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

      this.logger.debug(
        `2FA setup confirmed for user ${activeUser.userId} with ${result.recoveryCodes.length} recovery codes generated`
      )

      res.status(200).json({
        message: result.message,
        recoveryCodes: result.recoveryCodes
      })
    } catch (error) {
      this.logger.error(`Error in confirmTwoFactorSetup for user ${activeUser.userId}: ${error.message}`, error.stack)
      if (error instanceof HttpException) {
        throw error
      } else {
        throw new InternalServerErrorException('An error occurred during 2FA setup confirmation')
      }
    }
  }

  /**
   * Xác minh 2FA
   */
  @IsPublic()
  @Post('verify')
  @HttpCode(HttpStatus.OK)
  async verifyTwoFactor(
    @Body() body: TwoFactorVerifyDto,
    @Ip() ip: string,
    @UserAgent() userAgent: string,
    @Req() req: Request,
    @Res({ passthrough: false }) res: Response
  ): Promise<void> {
    try {
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

      this.logger.debug(`2FA verification successful for code from token ${sltCookieValue.substring(0, 15)}...`)

      // Kiểm tra nếu cần tiếp tục xác minh thiết bị (requiresDeviceVerification)
      if (result.requiresDeviceVerification) {
        res.status(200).json({
          message: result.message,
          requiresDeviceVerification: true
        })
      } else {
        // Trường hợp đăng nhập hoàn tất
        res.status(200).json({
          message: result.message,
          requiresDeviceVerification: false,
          user: result.user
        })
      }
    } catch (error) {
      this.logger.error(`Error in verifyTwoFactor: ${error.message}`, error.stack)
      if (error instanceof HttpException) {
        throw error
      } else {
        throw new InternalServerErrorException('An error occurred during 2FA verification')
      }
    }
  }

  /**
   * Tắt 2FA
   */
  @Post('disable')
  @UseGuards(AccessTokenGuard)
  @HttpCode(HttpStatus.OK)
  async disableTwoFactor(
    @ActiveUser() activeUser: AccessTokenPayload,
    @Body() body: DisableTwoFactorDto,
    @Ip() ip: string,
    @UserAgent() userAgent: string,
    @Req() req: Request,
    @Res({ passthrough: false }) res: Response
  ): Promise<void> {
    try {
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

      this.logger.debug(`2FA disabled for user ${activeUser.userId} using method ${body.method || 'default'}`)

      res.status(200).json({
        message: result.message
      })
    } catch (error) {
      this.logger.error(`Error in disableTwoFactor for user ${activeUser.userId}: ${error.message}`, error.stack)
      if (error instanceof HttpException) {
        throw error
      } else {
        throw new InternalServerErrorException('An error occurred during 2FA disabling')
      }
    }
  }

  /**
   * Tạo lại mã khôi phục
   */
  @Post('regenerate-recovery-codes')
  @UseGuards(AccessTokenGuard)
  @HttpCode(HttpStatus.OK)
  async regenerateRecoveryCodes(
    @ActiveUser() activeUser: AccessTokenPayload,
    @Body() body: RegenerateRecoveryCodesDto,
    @Ip() ip: string,
    @UserAgent() userAgent: string,
    @Res({ passthrough: false }) res: Response
  ): Promise<void> {
    try {
    const result = await this.twoFactorService.regenerateRecoveryCodes(activeUser.userId, body.code, ip, userAgent)

      this.logger.debug(
        `Recovery codes regenerated for user ${activeUser.userId}, total: ${result.recoveryCodes.length}`
      )

      res.status(200).json({
        message: result.message,
        recoveryCodes: result.recoveryCodes
      })
    } catch (error) {
      this.logger.error(`Error in regenerateRecoveryCodes for user ${activeUser.userId}: ${error.message}`, error.stack)
      if (error instanceof HttpException) {
        throw error
      } else {
        throw new InternalServerErrorException('An error occurred while regenerating recovery codes')
      }
    }
  }
}
