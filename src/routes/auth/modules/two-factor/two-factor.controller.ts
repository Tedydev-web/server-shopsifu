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
  HttpException,
  Inject,
  forwardRef
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
import { ICookieService } from 'src/shared/types/auth.types'
import { COOKIE_SERVICE } from 'src/shared/constants/injection.tokens'
import { CoreService } from '../core/core.service'

@Controller('auth/2fa')
export class TwoFactorController {
  private readonly logger = new Logger(TwoFactorController.name)

  constructor(
    private readonly twoFactorService: TwoFactorService,
    @Inject(COOKIE_SERVICE) private readonly cookieService: ICookieService,
    private readonly i18nService: I18nService<I18nTranslations>,
    @Inject(forwardRef(() => SessionsService))
    private readonly sessionsService: SessionsService,
    private readonly coreService: CoreService
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

      this.logger.debug(
        `2FA setup confirmed for user ${activeUser.userId} with ${result.recoveryCodes.length} recovery codes generated`
      )

      res.status(200).json({
        message: await this.i18nService.translate(result.message as I18nPath),
        recoveryCodes: result.recoveryCodes
      })
    } catch (error) {
      this.logger.error(`Error in confirmTwoFactorSetup for user ${activeUser.userId}: ${error.message}`, error.stack)
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
        body.method
      )

      this.logger.debug(
        `2FA verification result for code from token ${sltCookieValue.substring(0, 15)}...: ${result.message}`
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

        // Nếu là LOGIN_2FA, và xác minh thành công (không có lỗi nào được throw từ service)
        if (result.purpose === TypeOfVerificationCode.LOGIN_2FA && result.userId && result.metadata?.deviceId) {
          this.logger.debug(`Finalizing login for user ID: ${result.userId} after 2FA verification.`)

          const loginResult = await this.coreService.finalizeLoginAfterVerification(
            result.userId,
            result.metadata.deviceId,
            body.rememberMe || false,
            res, // Truyền res để CoreService có thể set cookie
            ip,
            userAgent
          )

          // CoreService.finalizeLoginAfterVerification đã set cookie và trả về auth tokens + user info
          // Nên wrapper nó trong một cấu trúc response chuẩn nếu cần
          res.status(HttpStatus.OK).json({
            message: await this.i18nService.translate(result.message as I18nPath), // Hoặc một message cụ thể hơn từ i18n
            accessToken: loginResult.accessToken,
            refreshToken: loginResult.refreshToken,
            user: loginResult.user
          })
          return
        }
      }

      // Kiểm tra nếu cần tiếp tục xác minh thiết bị (requiresDeviceVerification)
      // Trường hợp này chỉ xảy ra nếu mục đích không phải là LOGIN_2FA hoàn chỉnh,
      // ví dụ: 2FA thành công nhưng thiết bị mới và SLT được tạo cho mục đích xác minh thiết bị.
      if (result.requiresDeviceVerification) {
        res.status(HttpStatus.OK).json({
          message: await this.i18nService.translate(result.message as I18nPath), // Thông báo từ service có thể là "Vui lòng xác minh thiết bị của bạn"
          requiresDeviceVerification: true
          // Không có user data ở đây vì login chưa hoàn tất
        })
        return
      }

      // Fallback nếu không rơi vào các trường hợp trên (ví dụ: mục đích không xác định hoặc lỗi logic)
      // Hoặc nếu result.user được trả về cho mục đích không phải LOGIN_2FA (hiếm)
      // Thông thường, nếu mục đích là LOGIN_2FA, nó sẽ được xử lý ở trên.
      // Nếu là các mục đích khác không phải revoke, và không cần device verification,
      // thì có thể là một xác minh 2FA đơn thuần.
      // Tuy nhiên, hiện tại twoFactorService.verifyTwoFactor không có trường hợp này.
      // Nó sẽ throw lỗi nếu mã sai, hoặc trả về thông tin cho các flow cụ thể.

      // Nếu đến đây, có thể là một trạng thái không mong muốn hoặc một flow chưa được xử lý rõ ràng.
      // Trả về message từ service.
      this.logger.warn(`2FA verification handled with a generic response for purpose: ${result.purpose}`)
      res.status(HttpStatus.OK).json({
        message: await this.i18nService.translate(result.message as I18nPath),
        verifiedMethod: result.verifiedMethod
        // Không nên trả về user data ở đây trừ khi rất chắc chắn về flow
      })
    } catch (error) {
      this.logger.error(`Error in verifyTwoFactor controller: ${error.message}`, error.stack)
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
    this.logger.debug(`[handleRevokeSessionsVerification] User ${userId}, metadata: ${JSON.stringify(metadata)}`)
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
        message: await this.i18nService.translate(revokeResult.message as I18nPath),
        data: {
          revokedSessionsCount: revokeResult.revokedSessionsCount,
          untrustedDevicesCount: revokeResult.untrustedDevicesCount,
          revokedSessionIds: revokeResult.revokedSessionIds || [],
          revokedDeviceIds: revokeResult.revokedDeviceIds || [],
          requiresAdditionalVerification: false
        }
      })
    } catch (error) {
      this.logger.error(`[handleRevokeSessionsVerification] Error for user ${userId}: ${error.message}`, error.stack)
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
    this.logger.debug(`[handleRevokeAllSessionsVerification] User ${userId}, metadata: ${JSON.stringify(metadata)}`)
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
        message: await this.i18nService.translate(revokeResult.message as I18nPath),
        data: {
          revokedSessionsCount: revokeResult.revokedSessionsCount,
          untrustedDevicesCount: revokeResult.untrustedDevicesCount,
          revokedSessionIds: revokeResult.revokedSessionIds || [],
          revokedDeviceIds: revokeResult.revokedDeviceIds || [],
          requiresAdditionalVerification: false
        }
      })
    } catch (error) {
      this.logger.error(`[handleRevokeAllSessionsVerification] Error for user ${userId}: ${error.message}`, error.stack)
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

      this.logger.debug(`2FA disabled for user ${activeUser.userId}`)

      res.status(200).json({
        message: await this.i18nService.translate(result.message as I18nPath)
      })
    } catch (error) {
      this.logger.error(`Error in disableTwoFactor for user ${activeUser.userId}: ${error.message}`, error.stack)
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

      this.logger.debug(
        `Recovery codes regenerated for user ${activeUser.userId}, total: ${result.recoveryCodes.length}`
      )

      res.status(200).json({
        message: await this.i18nService.translate(result.message as I18nPath),
        recoveryCodes: result.recoveryCodes
      })
    } catch (error) {
      this.logger.error(`Error in regenerateRecoveryCodes for user ${activeUser.userId}: ${error.message}`, error.stack)
      this.cookieService.clearSltCookie(res)
      if (error instanceof HttpException) {
        throw error
      } else {
        throw AuthError.InternalServerError('An error occurred while regenerating recovery codes')
      }
    }
  }
}
