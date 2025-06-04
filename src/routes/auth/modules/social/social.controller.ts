import { Controller, Get, Post, Body, Query, Req, Res, Ip, HttpCode, HttpStatus, Logger, Inject } from '@nestjs/common'
import { Request, Response } from 'express'
import { SocialService } from './social.service'
import { UserAgent } from 'src/shared/decorators/user-agent.decorator'
import { ActiveUser } from 'src/shared/decorators/active-user.decorator'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'
import {
  CancelLinkDto,
  CancelLinkResponseDto,
  CompleteLinkDto,
  CompleteLinkResponseDto,
  GoogleAuthResponseDto,
  GoogleAuthSuccessResponseDto,
  GoogleAuthUrlQueryDto,
  GoogleAuthUrlResponseDto,
  GoogleCallbackQueryDto,
  TwoFactorRequiredResponseDto,
  DeviceVerificationRequiredResponseDto,
  AccountLinkingRequiredResponseDto,
  GoogleAuthErrorResponseDto,
  InitiateUnlinkDto,
  InitiateUnlinkResponseDto,
  LinkGoogleAccountDto,
  LinkGoogleAccountResponseDto,
  PendingLinkDetailsDto,
  UnlinkGoogleAccountDto,
  UnlinkGoogleAccountResponseDto,
  VerifyUnlinkDto,
  VerifyUnlinkResponseDto,
  VerifyAuthenticationDto,
  VerifyAuthenticationResponseDto,
  VerifyAuthenticationResponseUnion
} from './social.dto'
import { OtpService } from '../otp/otp.service'
import { TypeOfVerificationCode } from 'src/shared/constants/auth.constants'
import { IsPublic } from 'src/shared/decorators/auth.decorator'
import crypto from 'crypto'
import { CookieNames } from 'src/shared/constants/auth.constants'
import { ICookieService, ITokenService } from 'src/shared/types/auth.types'
import { COOKIE_SERVICE, TOKEN_SERVICE } from 'src/shared/constants/injection.tokens'

@Controller('auth/social')
export class SocialController {
  private readonly logger = new Logger(SocialController.name)

  constructor(
    private readonly socialService: SocialService,
    private readonly otpService: OtpService,
    @Inject(COOKIE_SERVICE) private readonly cookieService: ICookieService,
    @Inject(TOKEN_SERVICE) private readonly tokenService: ITokenService
  ) {}

  /**
   * Lấy URL xác thực Google
   * @description Endpoint thống nhất để tạo URL cho đăng nhập, đăng ký, liên kết Google OAuth
   * @public Endpoint này công khai, không yêu cầu xác thực
   */
  @IsPublic()
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
  ): Promise<
    | GoogleAuthSuccessResponseDto
    | TwoFactorRequiredResponseDto
    | DeviceVerificationRequiredResponseDto
    | AccountLinkingRequiredResponseDto
    | GoogleAuthErrorResponseDto
  > {
    const { code, state, error } = query
    const originalNonce = req.cookies?.[CookieNames.OAUTH_NONCE]

    this.logger.debug(
      `[googleCallback] Nhận callback từ Google với code: ${code ? 'có giá trị' : 'không có'}, state: ${state ? 'có giá trị' : 'không có'}`
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
      } as GoogleAuthErrorResponseDto
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
        } as GoogleAuthErrorResponseDto
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
        } as AccountLinkingRequiredResponseDto
      }

      // Xử lý các trường hợp xác thực bổ sung
      const { user, device, requiresTwoFactorAuth, requiresUntrustedDeviceVerification, twoFactorMethod } = result

      if (requiresTwoFactorAuth) {
        // Trường hợp yêu cầu xác thực 2FA
        this.logger.debug(`[googleCallback] Yêu cầu xác thực 2FA cho user: ${user.id}`)

        // Khởi tạo OTP với SLT cookie
        const sltJwt = await this.otpService.initiateOtpWithSltCookie({
          email: user.email,
          userId: user.id,
          deviceId: device.id,
          ipAddress: ip,
          userAgent,
          purpose: TypeOfVerificationCode.LOGIN_2FA,
          metadata: { twoFactorMethod }
        })

        // Set SLT cookie
        this.cookieService.setSltCookie(res, sltJwt, TypeOfVerificationCode.LOGIN_2FA)

        return {
          status: 'two_factor_required',
          data: {
            requiresTwoFactorAuth: true,
            twoFactorMethod: twoFactorMethod || undefined,
            message: result.message
          }
        } as TwoFactorRequiredResponseDto
      }

      if (requiresUntrustedDeviceVerification) {
        // Trường hợp thiết bị chưa được tin cậy
        this.logger.debug(`[googleCallback] Yêu cầu xác minh thiết bị không tin cậy cho user: ${user.id}`)

        // Khởi tạo OTP với SLT cookie
        const sltJwt = await this.otpService.initiateOtpWithSltCookie({
          email: user.email,
          userId: user.id,
          deviceId: device.id,
          ipAddress: ip,
          userAgent,
          purpose: TypeOfVerificationCode.LOGIN_UNTRUSTED_DEVICE_OTP
        })

        // Set SLT cookie
        this.cookieService.setSltCookie(res, sltJwt, TypeOfVerificationCode.LOGIN_UNTRUSTED_DEVICE_OTP)

        return {
          status: 'device_verification_required',
          data: {
            requiresDeviceVerification: true,
            message: result.message
          }
        } as DeviceVerificationRequiredResponseDto
      }

      // Trường hợp đăng nhập thành công
      this.logger.debug(`[googleCallback] Đăng nhập thành công cho user: ${user.id}`)

      // Hoàn tất quá trình đăng nhập, tạo cookies và session
      const userData = await this.socialService.finalizeSuccessfulAuth(user, device, true, res, ip, userAgent)

      return {
        status: 'success',
        user: userData
      } as GoogleAuthSuccessResponseDto
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
      } as GoogleAuthErrorResponseDto
    }
  }

  /**
   * Xác thực và xử lý tất cả các hoạt động liên quan đến xác thực
   * @description Endpoint thống nhất xử lý tất cả các loại xác thực, liên kết và thông tin liên kết
   * @public Endpoint này công khai, không yêu cầu xác thực AccessToken (trừ một số action)
   */
  @IsPublic()
  @Post('verify')
  @HttpCode(HttpStatus.OK)
  async verifyAuthentication(
    @Body() body: VerifyAuthenticationDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
    @UserAgent() userAgent: string,
    @Ip() ip: string,
    @ActiveUser() activeUser?: AccessTokenPayload
  ): Promise<VerifyAuthenticationResponseUnion> {
    const { action, code, password, rememberMe } = body
    const sltToken = req.cookies?.slt_token

    this.logger.debug(`[verifyAuthentication] Xử lý action ${action}`)

    try {
      // Khai báo biến kết quả để tránh lỗi lexical declaration
      let result2FA, resultDevice, linkResult, unlinkResult, pendingDetails, cancelResult

      // Xử lý theo loại hành động
      switch (action) {
        case '2fa':
          // Xác thực 2FA
          if (!code) throw new Error('Yêu cầu mã 2FA để xác minh')
          result2FA = await this.socialService.verifyTwoFactorAuth(sltToken || '', code, rememberMe, userAgent, ip, res)
          return result2FA

        case 'device':
          // Xác thực thiết bị không tin cậy
          if (!code) throw new Error('Yêu cầu mã OTP để xác minh')
          resultDevice = await this.socialService.verifyUntrustedDevice(sltToken || '', code, userAgent, ip, res)
          return resultDevice

        case 'link':
          // Xác minh và hoàn tất liên kết
          if (!password) throw new Error('Yêu cầu mật khẩu để xác minh')
          linkResult = await this.socialService.completeLinkAndLogin(req, res, userAgent, ip, password)
          return {
            status: 'success',
            message: 'Liên kết tài khoản thành công',
            user: linkResult
          }

        case 'unlink':
          // Xác minh và hủy liên kết
          if (!activeUser) throw new Error('Cần đăng nhập để hủy liên kết')
          unlinkResult = await this.socialService.verifyAndUnlinkGoogleAccount(
            activeUser.userId,
            sltToken,
            code,
            password,
            res
          )
          return {
            status: unlinkResult.success ? 'success' : 'error',
            message: unlinkResult.message
          }

        case 'pending-link-details':
          // Lấy thông tin liên kết đang chờ xử lý
          pendingDetails = await this.socialService.getPendingLinkDetails(req)
          return pendingDetails

        case 'cancel-link':
          // Hủy liên kết đang chờ xử lý
          cancelResult = await this.socialService.cancelPendingLink(req, res)
          return {
            status: 'success',
            message: cancelResult.message
          }

        default:
          throw new Error('Hành động không hợp lệ')
      }
    } catch (error) {
      this.logger.error(`[verifyAuthentication] Lỗi xác thực: ${error.message}`, error.stack)

      return {
        status: 'error',
        message: error.message || 'Xác thực thất bại'
      }
    }
  }
}
