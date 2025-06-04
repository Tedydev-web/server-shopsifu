import {
  Controller,
  Post,
  Body,
  HttpCode,
  HttpStatus,
  Req,
  Res,
  Ip,
  Logger,
  InternalServerErrorException,
  HttpException,
  Inject,
  forwardRef
} from '@nestjs/common'
import { Request, Response } from 'express'
import { I18nService } from 'nestjs-i18n'
import { ZodSerializerDto } from 'nestjs-zod'

import { TwoFactorService } from './two-factor.service'
import { UserAgent } from 'src/shared/decorators/user-agent.decorator'
import { ActiveUser } from 'src/shared/decorators/active-user.decorator'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'
import {
  TwoFactorConfirmSetupDto,
  TwoFactorVerifyDto,
  DisableTwoFactorDto,
  RegenerateRecoveryCodesDto,
  TwoFactorSetupResponseDto,
  TwoFactorConfirmSetupResponseDto,
  DisableTwoFactorResponseDto,
  RegenerateRecoveryCodesResponseDto
} from './dto/two-factor.dto'
import { CookieNames } from 'src/shared/constants/auth.constants'
import { AuthError } from 'src/routes/auth/auth.error'
import { IsPublic } from 'src/shared/decorators/auth.decorator'
import { TypeOfVerificationCode } from 'src/shared/constants/auth.constants'
import { SessionsService } from '../sessions/sessions.service'
import { ICookieService } from 'src/shared/types/auth.types'
import { COOKIE_SERVICE } from 'src/shared/constants/injection.tokens'

@Controller('auth/2fa')
export class TwoFactorController {
  private readonly logger = new Logger(TwoFactorController.name)

  constructor(
    private readonly twoFactorService: TwoFactorService,
    @Inject(COOKIE_SERVICE) private readonly cookieService: ICookieService,
    private readonly i18nService: I18nService,
    @Inject(forwardRef(() => SessionsService))
    private readonly sessionsService: SessionsService
  ) {}

  /**
   * Thiết lập 2FA
   */
  @Post('setup')
  @HttpCode(HttpStatus.OK)
  @ZodSerializerDto(TwoFactorSetupResponseDto)
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
  @HttpCode(HttpStatus.OK)
  @ZodSerializerDto(TwoFactorConfirmSetupResponseDto)
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
        res,
        body.method
      )

      this.logger.debug(`2FA verification successful for code from token ${sltCookieValue.substring(0, 15)}...`)

      // Xử lý các purpose đặc biệt
      if (result.purpose) {
        if (result.purpose === (TypeOfVerificationCode.REVOKE_SESSIONS as string) && result.userId && result.metadata) {
          await this.handleRevokeSessionsVerification(result.userId, result.metadata, ip, userAgent, res)
          return
        }

        if (
          result.purpose === (TypeOfVerificationCode.REVOKE_ALL_SESSIONS as string) &&
          result.userId &&
          result.metadata
        ) {
          await this.handleRevokeAllSessionsVerification(result.userId, result.metadata, ip, userAgent, res)
          return
        }
      }

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
   * Xử lý xác minh thu hồi sessions cụ thể thông qua 2FA
   */
  private async handleRevokeSessionsVerification(
    userId: number,
    metadata: any,
    ip: string,
    userAgent: string,
    res: Response
  ) {
    this.logger.debug(`[handleRevokeSessionsVerification] Processing for userId: ${userId}`)

    if (!metadata || (!metadata.sessionIds && !metadata.deviceIds)) {
      throw new Error('Không có thông tin sessions để thu hồi')
    }

    const options = {
      sessionIds: metadata.sessionIds,
      deviceIds: metadata.deviceIds,
      excludeCurrentSession: metadata.excludeCurrentSession ?? true
    }

    // Tạo active user để truyền vào service
    const activeUser = {
      userId,
      deviceId: metadata.deviceId || 0,
      sessionId: metadata.currentSessionId || '',
      email: metadata.email || '',
      roleId: 0,
      roleName: '',
      isDeviceTrustedInSession: false,
      exp: 0,
      iat: 0,
      jti: ''
    } as AccessTokenPayload

    const result = await this.sessionsService.revokeItems(
      userId,
      options,
      activeUser,
      undefined,
      undefined,
      ip,
      userAgent
    )

    // Xóa SLT cookie
    this.cookieService.clearSltCookie(res)

    res.status(200).json({
      message: result.message,
      data: {
        revokedSessionsCount: result.revokedSessionsCount,
        untrustedDevicesCount: result.untrustedDevicesCount,
        revokedSessionIds: result.revokedSessionIds || [],
        revokedDeviceIds: result.revokedDeviceIds || [],
        requiresAdditionalVerification: false
      }
    })
  }

  /**
   * Xử lý xác minh thu hồi tất cả sessions thông qua 2FA
   */
  private async handleRevokeAllSessionsVerification(
    userId: number,
    metadata: any,
    ip: string,
    userAgent: string,
    res: Response
  ) {
    this.logger.debug(`[handleRevokeAllSessionsVerification] Processing for userId: ${userId}`)

    if (!metadata) {
      throw new Error('Không có thông tin để thu hồi')
    }

    const options = {
      revokeAllUserSessions: true,
      excludeCurrentSession: metadata.excludeCurrentSession ?? true
    }

    // Tạo active user để truyền vào service
    const activeUser = {
      userId,
      deviceId: metadata.deviceId || 0,
      sessionId: metadata.currentSessionId || '',
      email: metadata.email || '',
      roleId: 0,
      roleName: '',
      isDeviceTrustedInSession: false,
      exp: 0,
      iat: 0,
      jti: ''
    } as AccessTokenPayload

    const result = await this.sessionsService.revokeItems(
      userId,
      options,
      activeUser,
      undefined,
      undefined,
      ip,
      userAgent
    )

    // Xóa SLT cookie
    this.cookieService.clearSltCookie(res)

    res.status(200).json({
      message: result.message,
      data: {
        revokedSessionsCount: result.revokedSessionsCount,
        untrustedDevicesCount: result.untrustedDevicesCount,
        revokedSessionIds: result.revokedSessionIds || [],
        revokedDeviceIds: result.revokedDeviceIds || [],
        requiresAdditionalVerification: false
      }
    })
  }

  /**
   * Tắt 2FA
   */
  @Post('disable')
  @HttpCode(HttpStatus.OK)
  @ZodSerializerDto(DisableTwoFactorResponseDto)
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
  @HttpCode(HttpStatus.OK)
  @ZodSerializerDto(RegenerateRecoveryCodesResponseDto)
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
