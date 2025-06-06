import {
  Controller,
  Get,
  Post,
  Body,
  Query,
  Req,
  Res,
  Ip,
  HttpCode,
  HttpStatus,
  Logger,
  Inject,
  forwardRef,
  BadRequestException,
  HttpException
} from '@nestjs/common'
import { Request, Response } from 'express'
import { SocialService } from './social.service'
import { UserAgent } from 'src/shared/decorators/user-agent.decorator'
import { ActiveUser } from 'src/routes/auth/shared/decorators/active-user.decorator'
import { AccessTokenPayload, ICookieService, ITokenService } from 'src/routes/auth/shared/auth.types'
import {
  GoogleAuthUrlQueryDto,
  GoogleCallbackQueryDto,
  VerifyAuthenticationDto,
  VerifyAuthenticationResponseUnion
} from './social.dto'
import { TypeOfVerificationCode, CookieNames } from 'src/routes/auth/shared/constants/auth.constants'
import { Auth, IsPublic } from 'src/routes/auth/shared/decorators/auth.decorator'
import crypto from 'crypto'
import { COOKIE_SERVICE, TOKEN_SERVICE } from 'src/shared/constants/injection.tokens'
import { UseZodGuard } from 'nestjs-zod'
import { Throttle } from '@nestjs/throttler'
import { AuthVerificationService } from '../../services/auth-verification.service'
import { AuthError } from 'src/routes/auth/auth.error'
import { CoreService } from 'src/routes/auth/modules/core/core.service'

@Auth()
@Controller('auth/social')
export class SocialController {
  private readonly logger = new Logger(SocialController.name)

  constructor(
    private readonly socialService: SocialService,
    @Inject(COOKIE_SERVICE) private readonly cookieService: ICookieService,
    @Inject(TOKEN_SERVICE) private readonly tokenService: ITokenService,
    @Inject(forwardRef(() => AuthVerificationService))
    private readonly authVerificationService: AuthVerificationService,
    private readonly coreService: CoreService
  ) {}

  /**
   * Lấy URL xác thực Google
   * @description Endpoint thống nhất để tạo URL cho đăng nhập, đăng ký, liên kết Google OAuth
   * @public Endpoint này công khai, không yêu cầu xác thực
   */
  @IsPublic()
  @Throttle({ default: { limit: 10, ttl: 60000 } })
  @Get('google')
  @HttpCode(HttpStatus.OK)
  getGoogleAuthUrl(
    @Query() query: GoogleAuthUrlQueryDto,
    @UserAgent() userAgent: string,
    @Ip() ip: string,
    @Res() res: Response,
    @ActiveUser() activeUser?: AccessTokenPayload
  ): void {
    try {
      // Xác định loại action: đăng nhập, đăng ký hoặc liên kết
      const action = query.action || 'login'
      this.logger.debug(`[getGoogleAuthUrl] Xử lý yêu cầu lấy URL xác thực Google với action: ${action}`)

      // Tạo nonce bảo mật để xác thực callback
      const nonce = crypto.randomBytes(16).toString('hex')
      this.logger.debug(`[getGoogleAuthUrl] Đã tạo nonce: ${nonce}`)

      // Lấy URL từ service
      const result = this.socialService.getGoogleAuthUrl({
        nonce,
        action, // Sử dụng action thay cho flow
        userId: activeUser?.userId,
        redirectUrl: query.redirectUrl
      })

      // Set nonce cookie để xác thực khi callback
      this.cookieService.setOAuthNonceCookie(res, result.nonce)

      // Trả về URL với format JSON thuần túy, không qua ZodSerializerDto
      this.logger.debug(`[getGoogleAuthUrl] URL xác thực Google đã được tạo thành công`)

      res.json({
        status: 'success',
        data: {
          url: result.url
        }
      })
    } catch (error) {
      this.logger.error(`[getGoogleAuthUrl] Lỗi tạo URL xác thực Google: ${error.message}`, error.stack)
      throw error
    }
  }

  /**
   * Xử lý callback từ Google
   * @description Xử lý dữ liệu mà Google trả về sau khi người dùng xác thực
   * @public Endpoint này công khai, không yêu cầu xác thực
   */
  @IsPublic()
  @Get('google/callback')
  @HttpCode(HttpStatus.OK)
  async googleCallback(
    @Query() query: GoogleCallbackQueryDto,
    @Res({ passthrough: true }) res: Response,
    @Req() req: Request,
    @UserAgent() userAgent: string,
    @Ip() ip: string
  ): Promise<any> {
    const { code, state, error } = query
    const originalNonce = req.cookies?.[CookieNames.OAUTH_NONCE]

    this.logger.debug(
      `[googleCallback] Nhận callback từ Google với code: ${
        code ? 'có giá trị' : 'không có'
      }, state: ${state ? 'có giá trị' : 'không có'}`
    )

    // Kiểm tra lỗi từ Google
    if (error) {
      this.logger.warn(`[googleCallback] Google trả về lỗi: ${error}`)
      return {
        status: 'error',
        error: {
          errorCode: 'GOOGLE_CALLBACK_ERROR',
          errorMessage: error,
          redirectToError: true
        }
      }
    }

    // Xóa nonce cookie vì đã hoàn tất callback
    this.cookieService.clearOAuthNonceCookie(res)

    try {
      // Xử lý callback
      this.logger.debug('[googleCallback] Gọi service xử lý callback')
      const result = await this.socialService.googleCallback({
        code,
        state,
        originalNonceFromCookie: originalNonce,
        userAgent,
        ip
      })

      if ('redirectToError' in result) {
        // Trường hợp lỗi
        this.logger.warn(`[googleCallback] Callback thất bại: ${result.errorCode} - ${result.errorMessage}`)
        return {
          status: 'error',
          error: result
        }
      }

      if ('needsLinking' in result) {
        // Trường hợp cần liên kết tài khoản
        this.logger.debug(`[googleCallback] Yêu cầu liên kết tài khoản: userId=${result.existingUserId}`)

        // Tạo token cho pending link
        const pendingLinkToken = this.tokenService.signPendingLinkToken({
          existingUserId: result.existingUserId,
          googleId: result.googleId,
          googleEmail: result.googleEmail,
          googleName: result.googleName,
          googleAvatar: result.googleAvatar
        })

        // Set cookie cho pending link
        this.cookieService.setOAuthPendingLinkTokenCookie(res, pendingLinkToken)

        return {
          status: 'linking_required',
          data: {
            needsLinking: true,
            existingUserId: result.existingUserId,
            existingUserEmail: result.existingUserEmail,
            googleId: result.googleId,
            googleEmail: result.googleEmail,
            googleName: result.googleName || null,
            googleAvatar: result.googleAvatar || null,
            message: result.message
          }
        }
      }

      const { user, device } = result

      const verificationResult = await this.authVerificationService.initiateVerification(
        {
          userId: user.id,
          deviceId: device.id,
          email: user.email,
          ipAddress: ip,
          userAgent: userAgent,
          purpose: TypeOfVerificationCode.LOGIN,
          rememberMe: true, // Google login is treated as rememberMe=true
          metadata: { from: 'google-login' }
        },
        res
      )

      return {
        statusCode: HttpStatus.OK,
        message: verificationResult.message,
        data: {
          ...verificationResult
        }
      }
    } catch (error) {
      this.logger.error(`[googleCallback] Lỗi xử lý callback: ${error.message}`, error.stack)

      // Trả về lỗi định dạng chuẩn
      return {
        status: 'error',
        error: {
          errorCode: 'INTERNAL_SERVER_ERROR',
          errorMessage: 'Đã xảy ra lỗi trong quá trình xử lý đăng nhập Google. Vui lòng thử lại sau.',
          redirectToError: true
        }
      }
    }
  }

  /**
   * Xác thực và xử lý tất cả các hoạt động liên quan đến xác thực
   * @description Endpoint thống nhất xử lý tất cả các loại xác thực, liên kết và thông tin liên kết
   * @public Endpoint này công khai, không yêu cầu xác thực AccessToken (trừ một số action)
   */
  @IsPublic()
  @Throttle({ default: { limit: 5, ttl: 60000 } })
  @Post('verify')
  @UseZodGuard('body', VerifyAuthenticationDto)
  @HttpCode(HttpStatus.OK)
  async verifyAuthentication(
    @Body() body: VerifyAuthenticationDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
    @UserAgent() userAgent: string,
    @Ip() ip: string,
    @ActiveUser() activeUser?: AccessTokenPayload
  ): Promise<VerifyAuthenticationResponseUnion> {
    const { purpose, sltToken, code, password } = body
    const userId = activeUser?.userId

    try {
      if (purpose === 'UNLINK_GOOGLE_ACCOUNT') {
        if (!userId) throw AuthError.InsufficientPermissions()

        const result = await this.authVerificationService.verifyCode(sltToken || '', code || '', ip, userAgent, res)

        if (!result.success) {
          throw new HttpException(result.message, HttpStatus.BAD_REQUEST)
        }
        // This response shape matches VerifyAuthenticationResponseDto
        return { success: true, message: result.message }
      }

      if (purpose === 'LINK_ACCOUNT') {
        const { user, device } = await this.socialService.completeLinkAndLogin(req, res, userAgent, ip, password || '')
        const finalizedAuth = await this.coreService.finalizeLoginAndCreateTokens(
          user,
          device,
          true,
          res,
          ip,
          userAgent
        )
        // This response shape matches VerifyAuthenticationResponseDto
        return {
          success: true,
          message: 'Account linked and logged in successfully.',
          data: {
            user: finalizedAuth.user
          }
        }
      }

      throw new BadRequestException('Invalid purpose for social verification')
    } catch (error) {
      this.logger.error(`[verifyAuthentication] Error: ${error.message}`, error.stack)
      if (error instanceof HttpException) throw error
      throw AuthError.InternalServerError(error.message)
    }
  }

  @Post('unlink')
  @HttpCode(HttpStatus.OK)
  async initiateUnlinkGoogleAccount(
    @ActiveUser() activeUser: AccessTokenPayload,
    @Ip() ip: string,
    @UserAgent() userAgent: string,
    @Res({ passthrough: true }) res: Response
  ): Promise<any> {
    this.logger.debug(`[initiateUnlinkGoogleAccount] User ${activeUser.userId} is initiating Google account unlinking.`)

    if (!activeUser.email) {
      throw AuthError.InternalServerError('Active user email is missing in the token.')
    }

    const verificationResult = await this.authVerificationService.initiateVerification(
      {
        userId: activeUser.userId,
        deviceId: activeUser.deviceId,
        email: activeUser.email,
        ipAddress: ip,
        userAgent,
        purpose: TypeOfVerificationCode.UNLINK_GOOGLE_ACCOUNT,
        metadata: {}
      },
      res
    )

    return {
      success: true,
      message: verificationResult.message,
      verificationType: verificationResult.verificationType,
      sltToken: verificationResult.sltToken
    }
  }
}
