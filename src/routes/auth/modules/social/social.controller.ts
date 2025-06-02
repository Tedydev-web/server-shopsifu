import {
  Controller,
  Get,
  Post,
  Body,
  Query,
  Req,
  Res,
  UseGuards,
  Ip,
  HttpCode,
  HttpStatus,
  Logger
} from '@nestjs/common'
import { Request, Response } from 'express'
import { ZodSerializerDto } from 'nestjs-zod'
import { SocialService } from './social.service'
import { UserAgent } from 'src/shared/decorators/user-agent.decorator'
import { AccessTokenGuard } from 'src/routes/auth/guards/access-token.guard'
import { ActiveUser } from 'src/routes/auth/decorators/active-user.decorator'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'
import {
  CancelLinkDto,
  CancelLinkResponseDto,
  CompleteLinkDto,
  CompleteLinkResponseDto,
  GoogleAuthUrlQueryDto,
  GoogleAuthUrlResponseDto,
  GoogleCallbackQueryDto,
  GoogleCallbackResponseDto,
  LinkGoogleAccountDto,
  LinkGoogleAccountResponseDto,
  PendingLinkDetailsDto
} from './dto/social.dto'
import { OtpService } from '../otp/otp.service'
import { TypeOfVerificationCode } from 'src/routes/auth/constants/auth.constants'
import { CookieService } from 'src/routes/auth/shared/cookie/cookie.service'
import { TokenService } from 'src/routes/auth/shared/token/token.service'
import { IsPublic } from 'src/routes/auth/decorators/auth.decorator'

@Controller('auth/social')
export class SocialController {
  private readonly logger = new Logger(SocialController.name)

  constructor(
    private readonly socialService: SocialService,
    private readonly otpService: OtpService,
    private readonly cookieService: CookieService,
    private readonly tokenService: TokenService
  ) {}

  /**
   * Lấy URL xác thực Google
   */
  @IsPublic()
  @Get('google/url')
  @ZodSerializerDto(GoogleAuthUrlResponseDto)
  getGoogleAuthUrl(
    @Query() query: GoogleAuthUrlQueryDto,
    @UserAgent() userAgent: string,
    @Ip() ip: string,
    @Res({ passthrough: true }) res: Response,
    @ActiveUser() activeUser?: AccessTokenPayload
  ): GoogleAuthUrlResponseDto {
    const flow = query.flow || 'login'
    const { url, nonce } = this.socialService.getGoogleAuthUrl({
      nonce: '',
      flow,
      userId: activeUser?.userId
    })

    // Set nonce cookie
    this.cookieService.setOAuthNonceCookie(res, nonce)

    return { url }
  }

  /**
   * Xử lý callback từ Google
   */
  @IsPublic()
  @Get('google/callback')
  async googleCallback(
    @Query() query: GoogleCallbackQueryDto,
    @Res({ passthrough: true }) res: Response,
    @Req() req: Request,
    @UserAgent() userAgent: string,
    @Ip() ip: string
  ): Promise<GoogleCallbackResponseDto | Record<string, any>> {
    const { code, state, error } = query

    // Kiểm tra lỗi từ Google
    if (error) {
      return {
        errorCode: 'GOOGLE_CALLBACK_ERROR',
        errorMessage: error,
        redirectToError: true
      }
    }

    // Xử lý callback
    const result = await this.socialService.googleCallback({
      code,
      state,
      userAgent,
      ip
    })

    // Xóa nonce cookie
    this.cookieService.clearOAuthNonceCookie(res)

    // Xử lý các trường hợp khác nhau
    if ('redirectToError' in result) {
      return result
    }

    if ('needsLinking' in result) {
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
        needsLinking: true,
        message: result.message
      }
    }

    // Xử lý trường hợp thành công
    const { user, device, requiresTwoFactorAuth, requiresUntrustedDeviceVerification } = result

    // Nếu yêu cầu 2FA
    if (requiresTwoFactorAuth) {
      // Khởi tạo OTP với SLT cookie
      const sltJwt = await this.otpService.initiateOtpWithSltCookie({
        email: user.email,
        userId: user.id,
        deviceId: device.id,
        ipAddress: ip,
        userAgent,
        purpose: TypeOfVerificationCode.LOGIN_2FA,
        metadata: {
          twoFactorMethod: user.twoFactorMethod
        }
      })

      // Set SLT cookie
      this.cookieService.setSltCookie(res, sltJwt, TypeOfVerificationCode.LOGIN_2FA)

      return {
        requiresTwoFactorAuth: true,
        message: result.message
      }
    }

    // Nếu thiết bị chưa được tin tưởng
    if (requiresUntrustedDeviceVerification) {
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
        requiresDeviceVerification: true,
        message: result.message
      }
    }

    // Đăng nhập thành công
    return this.socialService.finalizeSuccessfulAuth(user, device, true, res)
  }

  /**
   * Liên kết tài khoản Google
   */
  @Post('google/link')
  @UseGuards(AccessTokenGuard)
  @HttpCode(HttpStatus.OK)
  @ZodSerializerDto(LinkGoogleAccountResponseDto)
  async linkGoogleAccount(
    @ActiveUser() activeUser: AccessTokenPayload,
    @Body() body: LinkGoogleAccountDto
  ): Promise<LinkGoogleAccountResponseDto> {
    return this.socialService.linkGoogleAccount(activeUser.userId, body.googleIdToken)
  }

  /**
   * Lấy thông tin liên kết đang chờ
   */
  @IsPublic()
  @Get('google/pending-link')
  @ZodSerializerDto(PendingLinkDetailsDto)
  async getPendingLinkDetails(@Req() req: Request): Promise<PendingLinkDetailsDto> {
    return this.socialService.getPendingLinkDetails(req)
  }

  /**
   * Hoàn thành liên kết tài khoản Google và đăng nhập
   */
  @IsPublic()
  @Post('google/complete-link')
  @HttpCode(HttpStatus.OK)
  async completeLinkAndLogin(
    @Body() body: CompleteLinkDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
    @UserAgent() userAgent: string,
    @Ip() ip: string
  ): Promise<CompleteLinkResponseDto> {
    try {
      const result = await this.socialService.completeLinkAndLogin(req, res, userAgent, ip, body.password)

      // Xóa cookie pending link sau khi hoàn thành
      this.cookieService.clearOAuthPendingLinkTokenCookie(res)

      return result
    } catch (error) {
      this.logger.error(`Error completing Google account link: ${error.message}`, error.stack)
      throw error
    }
  }

  /**
   * Hủy liên kết đang chờ xử lý
   */
  @IsPublic()
  @Post('google/cancel-link')
  @HttpCode(HttpStatus.OK)
  async cancelPendingLink(
    @Body() _: CancelLinkDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response
  ): Promise<CancelLinkResponseDto> {
    try {
      const result = await this.socialService.cancelPendingLink(req, res)

      // Xóa cookie pending link sau khi hủy
      this.cookieService.clearOAuthPendingLinkTokenCookie(res)

      return result
    } catch (error) {
      this.logger.error(`Error cancelling pending Google link: ${error.message}`, error.stack)
      throw error
    }
  }
}
