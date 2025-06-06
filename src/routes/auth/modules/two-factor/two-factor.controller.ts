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
  Logger,
  BadRequestException
} from '@nestjs/common'
import { Request, Response } from 'express'
import { I18nService } from 'nestjs-i18n'
import { I18nTranslations, I18nPath } from 'src/generated/i18n.generated'
import { ZodSerializerDto } from 'nestjs-zod'

import { TwoFactorService } from './two-factor.service'
import { UserAgent } from 'src/shared/decorators/user-agent.decorator'
import { ActiveUser } from 'src/shared/decorators/active-user.decorator'
import { AccessTokenPayload } from 'src/routes/auth/shared/jwt.type'
import {
  TwoFactorConfirmSetupDto,
  TwoFactorVerifyDto,
  DisableTwoFactorDto,
  RegenerateRecoveryCodesDto,
  TwoFactorSetupResponseDto,
  TwoFactorConfirmSetupResponseDto,
  DisableTwoFactorResponseDto,
  RegenerateRecoveryCodesResponseDto
} from './two-factor.dto'
import { CookieNames } from 'src/shared/constants/auth.constants'
import { AuthError } from '../../auth.error'
import { IsPublic, Auth } from 'src/shared/decorators/auth.decorator'
import { TypeOfVerificationCode } from 'src/shared/constants/auth.constants'
import { SessionsService } from '../sessions/sessions.service'
import { ICookieService, ITokenService } from 'src/routes/auth/shared/auth.types'
import { COOKIE_SERVICE, REDIS_SERVICE, TOKEN_SERVICE } from 'src/shared/constants/injection.tokens'
import { CoreService } from '../core/core.service'
import { RedisService } from 'src/providers/redis/redis.service'
import { RedisKeyManager } from 'src/shared/utils/redis-keys.utils'
import { AuthVerificationService } from 'src/routes/auth/services/auth-verification.service'
import { SLTService } from 'src/routes/auth/shared/services/slt.service'

interface RevokeSessionsMetadata {
  sessionIds?: string[]
  deviceIds?: number[]
  revokeAllUserSessions?: boolean
  excludeCurrentSession?: boolean
  currentSessionIdToExclude?: string
  currentDeviceIdToExclude?: number
}

interface VerificationResult {
  message: string
  verifiedMethod: string
  requiresDeviceVerification?: boolean
  purpose?: TypeOfVerificationCode
  userId?: number
  metadata?: any
}

interface DeviceVerificationMetadata {
  deviceId: number
}

@Auth([])
@IsPublic()
@Controller('auth/2fa')
export class TwoFactorController {
  private readonly logger = new Logger(TwoFactorController.name)

  constructor(
    private readonly twoFactorService: TwoFactorService,
    @Inject(forwardRef(() => AuthVerificationService))
    private readonly authVerificationService: AuthVerificationService,
    @Inject(COOKIE_SERVICE) private readonly cookieService: ICookieService,
    private readonly i18nService: I18nService<I18nTranslations>,
    @Inject(forwardRef(() => SessionsService))
    private readonly sessionsService: SessionsService,
    private readonly coreService: CoreService,
    @Inject(REDIS_SERVICE) private readonly redisService: RedisService,
    @Inject(TOKEN_SERVICE) private readonly tokenService: ITokenService
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
    @Res({ passthrough: true }) res: Response
  ): Promise<any> {
    this.logger.log(`[setupTwoFactor] Setting up 2FA for user: ${activeUser.userId}`)

    try {
      // Thiết lập 2FA
      const setupData = await this.twoFactorService.setupVerification(activeUser.userId, {
        deviceId: activeUser.deviceId,
        ip,
        userAgent,
        res
      })

      return {
        success: true,
        message: this.i18nService.t('auth.Auth.2FA.Setup.Success'),
        secret: setupData.secret,
        uri: setupData.uri
      }
    } catch (error) {
      this.logger.error(`[setupTwoFactor] Error: ${error.message}`, error.stack)
      if (error instanceof AuthError) {
        throw error
      }
      throw new BadRequestException(error.message)
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
    @Body() body: TwoFactorVerifyDto,
    @Ip() ip: string,
    @UserAgent() userAgent: string,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response
  ): Promise<any> {
    this.logger.log(`[confirmTwoFactorSetup] Confirming 2FA setup for user: ${activeUser.userId}`)

    try {
      // Get SLT cookie
      const sltCookieValue = req.cookies?.slt_token

      if (!sltCookieValue) {
        throw AuthError.SLTCookieMissing()
      }

      // Xác nhận thiết lập 2FA
      const result = await this.twoFactorService.confirmTwoFactorSetup(
        activeUser.userId,
        sltCookieValue,
        body.code,
        ip,
        userAgent,
        res
      )

      // Xóa SLT cookie
      this.cookieService.clearSltCookie(res)

      return {
        success: true,
        message: result.message,
        recoveryCodes: result.recoveryCodes
      }
    } catch (error) {
      this.logger.error(`[confirmTwoFactorSetup] Error: ${error.message}`, error.stack)

      // Clear SLT cookie in case of error
      this.cookieService.clearSltCookie(res)

      if (error instanceof AuthError) {
        throw error
      }

      throw new BadRequestException(error.message)
    }
  }

  /**
   * Xác minh 2FA
   */
  @Post('verify')
  async verifyTwoFactor(
    @Body() body: TwoFactorVerifyDto,
    @Ip() ip: string,
    @UserAgent() userAgent: string,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response
  ): Promise<any> {
    this.logger.log(`[verifyTwoFactor] Verifying 2FA for method: ${body.method}`)

    try {
      // Get SLT cookie
      const sltCookieValue = req.cookies?.slt_token

      if (!sltCookieValue) {
        throw AuthError.SLTCookieMissing()
      }

      // Sử dụng AuthVerificationService để xác minh 2FA
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

      // Trả về kết quả thích hợp
      return {
        success: verificationResult.success,
        message: verificationResult.message,
        requiresDeviceVerification: verificationResult.requiresDeviceVerification,
        requiresAdditionalVerification: verificationResult.requiresAdditionalVerification,
        redirectUrl: verificationResult.redirectUrl,
        user: verificationResult.user
      }
    } catch (error) {
      this.logger.error(`[verifyTwoFactor] Error: ${error.message}`, error.stack)

      // Clear SLT cookie in case of error
      this.cookieService.clearSltCookie(res)

      if (error instanceof AuthError) {
        throw error
      }

      throw new BadRequestException(error.message)
    }
  }

  /**
   * Vô hiệu hóa 2FA
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
    @Res({ passthrough: true }) res: Response
  ): Promise<any> {
    this.logger.log(`[disableTwoFactor] Disabling 2FA for user: ${activeUser.userId}`)

    try {
      // Khởi tạo luồng xác thực để vô hiệu hóa 2FA
      const verificationResult = await this.authVerificationService.initiateVerification(
        {
          userId: activeUser.userId,
          deviceId: activeUser.deviceId,
          email: activeUser.email || '',
          ipAddress: ip,
          userAgent,
          purpose: TypeOfVerificationCode.DISABLE_2FA,
          metadata: {
            method: body.method
          }
        },
        res
      )

      return {
        success: true,
        message: verificationResult.message
      }
    } catch (error) {
      this.logger.error(`[disableTwoFactor] Error: ${error.message}`, error.stack)
      if (error instanceof AuthError) {
        throw error
      }
      throw new BadRequestException(error.message)
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
    @Res({ passthrough: true }) res: Response
  ): Promise<any> {
    this.logger.log(`[regenerateRecoveryCodes] Regenerating recovery codes for user: ${activeUser.userId}`)

    try {
      // Tạo lại mã khôi phục
      const recoveryCodes = await this.twoFactorService.regenerateRecoveryCodes(activeUser.userId, body.code, {
        ip,
        userAgent
      })

      return {
        success: true,
        message: this.i18nService.t('auth.Auth.2FA.RecoveryCodesRegenerated'),
        recoveryCodes
      }
    } catch (error) {
      this.logger.error(`[regenerateRecoveryCodes] Error: ${error.message}`, error.stack)
      if (error instanceof AuthError) {
        throw error
      }
      throw new BadRequestException(error.message)
    }
  }
}
