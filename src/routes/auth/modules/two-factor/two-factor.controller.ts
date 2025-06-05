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
} from './two-factor.dto'
import { CookieNames } from 'src/shared/constants/auth.constants'
import { AuthError } from 'src/routes/auth/auth.error'
import { IsPublic } from 'src/shared/decorators/auth.decorator'
import { TypeOfVerificationCode } from 'src/shared/constants/auth.constants'
import { SessionsService } from '../sessions/sessions.service'
import { ICookieService, ITokenService } from 'src/shared/types/auth.types'
import { COOKIE_SERVICE, REDIS_SERVICE, TOKEN_SERVICE } from 'src/shared/constants/injection.tokens'
import { CoreService } from '../core/core.service'
import { RedisService } from 'src/shared/providers/redis/redis.service'
import { RedisKeyManager } from 'src/shared/utils/redis-keys.utils'

@Controller('auth/2fa')
export class TwoFactorController {
  private readonly logger = new Logger(TwoFactorController.name)

  constructor(
    private readonly twoFactorService: TwoFactorService,
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

      // Trả về response trực tiếp từ controller để tránh serialization pipeline của NestJS
      res.status(200).json({
        secret: result.secret,
        uri: result.uri
      })
    } catch (error) {
      // Xử lý lỗi và trả về response thích hợp
      if (error instanceof HttpException) {
        throw error
      } else {
        throw AuthError.InternalServerError('An error occurred during 2FA setup')
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

      res.status(200).json({
        message: await this.i18nService.t(result.message as I18nPath),
        recoveryCodes: result.recoveryCodes
      })
    } catch (error) {
      if (error instanceof HttpException) {
        throw error
      } else {
        throw AuthError.InternalServerError('An error occurred during 2FA setup confirmation')
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
  ): Promise<Response<any, Record<string, any>> | void> {
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
        body.method
      )

      // Xử lý các purpose đặc biệt
      if (result.purpose) {
        if (result.purpose === TypeOfVerificationCode.REVOKE_SESSIONS && result.userId && result.metadata) {
          await this.handleRevokeSessionsVerification(result.userId, result.metadata, ip, userAgent, res)
          return
        }

        if (result.purpose === TypeOfVerificationCode.REVOKE_ALL_SESSIONS && result.userId && result.metadata) {
          await this.handleRevokeAllSessionsVerification(result.userId, result.metadata, ip, userAgent, res)
          return
        }

        // Nếu là LOGIN_UNTRUSTED_DEVICE_2FA, và xác minh thành công (không có lỗi nào được throw từ service)
        if (
          result.purpose === TypeOfVerificationCode.LOGIN_UNTRUSTED_DEVICE_2FA &&
          result.userId &&
          result.metadata?.deviceId
        ) {
          const loginResult = await this.coreService.finalizeLoginAfterVerification(
            result.userId,
            result.metadata.deviceId,
            body.rememberMe || false,
            res, // Truyền res để CoreService có thể set cookie
            ip,
            userAgent
          )

          // Xóa cờ device:needs_reverify_after_revoke sau khi xác minh thành công
          const reverifyFlagKey = RedisKeyManager.customKey(
            'device:needs_reverify_after_revoke',
            result.metadata.deviceId.toString()
          )
          await this.redisService.del(reverifyFlagKey)
          this.logger.debug(
            `[verifyTwoFactor] Cleared reverify_after_revoke flag for device ${result.metadata.deviceId}`
          )

          // ALSO CLEAR THE ADMIN REVERIFICATION FLAG
          await this.tokenService.clearDeviceReverification(result.userId, result.metadata.deviceId)
          this.logger.debug(
            `[verifyTwoFactor] Cleared admin reverification flag for device ${result.metadata.deviceId}`
          )

          // Prepare user response with picked UserProfile fields
          const userResponseFor2FA = {
            ...loginResult.user,
            userProfile: loginResult.user.userProfile
              ? {
                  username: loginResult.user.userProfile.username,
                  avatar: loginResult.user.userProfile.avatar
                }
              : null
          }

          // Login is finalized, user object is present
          const dataPayload: { user: any; askToTrustDevice?: boolean } = {
            user: userResponseFor2FA // Use the modified userResponseFor2FA
          }

          // Include askToTrustDevice if it's relevant
          if (typeof loginResult.askToTrustDevice === 'boolean') {
            dataPayload.askToTrustDevice = loginResult.askToTrustDevice
          }

          this.cookieService.clearSltCookie(res) // Clear SLT cookie after successful 2FA login

          // Send the success response
          return res.status(HttpStatus.OK).json({
            statusCode: HttpStatus.OK,
            message: await this.i18nService.t(result.message as I18nPath),
            data: dataPayload // Use the structured dataPayload
          })
        }
      }

      // Kiểm tra nếu cần tiếp tục xác minh thiết bị (requiresDeviceVerification)
      // Trường hợp này chỉ xảy ra nếu mục đích không phải là LOGIN_UNTRUSTED_DEVICE_2FA hoàn chỉnh,
      // ví dụ: 2FA thành công nhưng thiết bị mới và SLT được tạo cho mục đích xác minh thiết bị.
      if (result.requiresDeviceVerification) {
        res.status(HttpStatus.OK).json({
          message: await this.i18nService.t(result.message as I18nPath), // Thông báo từ service có thể là "Vui lòng xác minh thiết bị của bạn"
          requiresDeviceVerification: true
          // Không có user data ở đây vì login chưa hoàn tất
        })
        return
      }

      // Fallback nếu không rơi vào các trường hợp trên (ví dụ: mục đích không xác định hoặc lỗi logic)
      // Hoặc nếu result.user được trả về cho mục đích không phải LOGIN_UNTRUSTED_DEVICE_2FA (hiếm)
      // Thông thường, nếu mục đích là LOGIN_UNTRUSTED_DEVICE_2FA, nó sẽ được xử lý ở trên.
      // Nếu là các mục đích khác không phải revoke, và không cần device verification,
      // thì có thể là một xác minh 2FA đơn thuần.
      // Tuy nhiên, hiện tại twoFactorService.verifyTwoFactor không có trường hợp này.
      // Nó sẽ throw lỗi nếu mã sai, hoặc trả về thông tin cho các flow cụ thể.

      // Nếu đến đây, có thể là một trạng thái không mong muốn hoặc một flow chưa được xử lý rõ ràng.
      // Trả về message từ service.
      res.status(HttpStatus.OK).json({
        message: await this.i18nService.t(result.message as I18nPath),
        verifiedMethod: result.verifiedMethod
        // Không nên trả về user data ở đây trừ khi rất chắc chắn về flow
      })
    } catch (error) {
      // Xóa SLT cookie nếu có lỗi để tránh kẹt ở trạng thái lỗi
      this.cookieService.clearSltCookie(res)
      if (error instanceof HttpException) {
        throw error
      } else {
        throw AuthError.InternalServerError('An error occurred during 2FA verification')
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
    try {
      const revokeResult = await this.sessionsService.revokeItems(
        userId,
        {
          sessionIds: metadata.sessionIds,
          deviceIds: metadata.deviceIds,
          excludeCurrentSession: metadata.excludeCurrentSession ?? true
        },
        {
          sessionId: metadata.currentSessionIdToExclude,
          deviceId: metadata.currentDeviceIdToExclude
        },
        undefined,
        undefined,
        ip,
        userAgent
      )

      this.cookieService.clearSltCookie(res)
      res.status(200).json({
        message: await this.i18nService.t(revokeResult.message as I18nPath),
        data: {
          revokedSessionsCount: revokeResult.revokedSessionsCount,
          untrustedDevicesCount: revokeResult.untrustedDevicesCount,
          revokedSessionIds: revokeResult.revokedSessionIds || [],
          revokedDeviceIds: revokeResult.revokedDeviceIds || [],
          requiresAdditionalVerification: false
        }
      })
    } catch (error) {
      this.cookieService.clearSltCookie(res)
      if (error instanceof HttpException) throw error
      throw AuthError.InternalServerError(error.message)
    }
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
    try {
      const revokeResult = await this.sessionsService.revokeItems(
        userId,
        {
          revokeAllUserSessions: true,
          excludeCurrentSession: metadata.excludeCurrentSession ?? true
        },
        {
          sessionId: metadata.currentSessionIdToExclude,
          deviceId: metadata.currentDeviceIdToExclude
        },
        undefined,
        undefined,
        ip,
        userAgent
      )

      this.cookieService.clearSltCookie(res)
      res.status(200).json({
        message: await this.i18nService.t(revokeResult.message as I18nPath),
        data: {
          revokedSessionsCount: revokeResult.revokedSessionsCount,
          untrustedDevicesCount: revokeResult.untrustedDevicesCount,
          revokedSessionIds: revokeResult.revokedSessionIds || [],
          revokedDeviceIds: revokeResult.revokedDeviceIds || [],
          requiresAdditionalVerification: false
        }
      })
    } catch (error) {
      this.cookieService.clearSltCookie(res)
      if (error instanceof HttpException) throw error
      throw AuthError.InternalServerError(error.message)
    }
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

      res.status(200).json({
        message: await this.i18nService.t(result.message as I18nPath)
      })
    } catch (error) {
      this.cookieService.clearSltCookie(res)
      if (error instanceof HttpException) {
        throw error
      } else {
        throw AuthError.InternalServerError('An error occurred while disabling 2FA')
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

      res.status(200).json({
        message: await this.i18nService.t(result.message as I18nPath),
        recoveryCodes: result.recoveryCodes
      })
    } catch (error) {
      this.cookieService.clearSltCookie(res)
      if (error instanceof HttpException) {
        throw error
      } else {
        throw AuthError.InternalServerError('An error occurred while regenerating recovery codes')
      }
    }
  }
}
