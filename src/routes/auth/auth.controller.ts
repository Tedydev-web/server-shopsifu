import { Body, Controller, Get, HttpCode, HttpStatus, Ip, Post, Query, Req, Res, Logger } from '@nestjs/common'
import { Response, Request } from 'express'
import { ZodSerializerDto } from 'nestjs-zod'
import {
  DisableTwoFactorBodyDTO,
  GetAuthorizationUrlResDTO,
  LoginBodyDTO,
  LogoutBodyDTO,
  RefreshTokenBodyDTO,
  RefreshTokenResDTO,
  RegisterBodyDTO,
  RegisterResDTO,
  ResetPasswordBodyDTO,
  SendOTPBodyDTO,
  TwoFactorSetupResDTO,
  TwoFactorVerifyBodyDTO,
  VerifyCodeBodyDTO,
  VerifyCodeResDTO,
  TwoFactorConfirmSetupBodyDTO,
  TwoFactorConfirmSetupResDTO,
  TrustDeviceBodyDTO,
  RememberMeBodyDTO,
  RefreshTokenSuccessResDTO
} from 'src/routes/auth/auth.dto'
import { UserProfileResSchema, LoginSessionResSchema } from 'src/routes/auth/auth.model'
import { UseZodSchemas, hasProperty } from 'src/shared/decorators/use-zod-schema.decorator'

import { AuthService } from 'src/routes/auth/auth.service'
import { GoogleService } from 'src/routes/auth/google.service'
import envConfig from 'src/shared/config'
import { ActiveUser } from 'src/shared/decorators/active-user.decorator'
import { IsPublic } from 'src/shared/decorators/auth.decorator'
import { UserAgent } from 'src/shared/decorators/user-agent.decorator'
import { EmptyBodyDTO } from 'src/shared/dtos/request.dto'
import { MessageResDTO } from 'src/shared/dtos/response.dto'
import { TokenService } from 'src/shared/services/token.service'
import { SkipThrottle, Throttle } from '@nestjs/throttler'
import { CookieNames } from 'src/shared/constants/auth.constant'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'

@Controller('auth')
export class AuthController {
  private readonly logger = new Logger(AuthController.name)

  constructor(
    private readonly authService: AuthService,
    private readonly googleService: GoogleService,
    private readonly tokenService: TokenService
  ) {}

  @Post('register')
  @IsPublic()
  @ZodSerializerDto(RegisterResDTO)
  @Throttle({ short: { limit: 5, ttl: 10000 }, long: { limit: 20, ttl: 60000 } })
  register(@Body() body: RegisterBodyDTO, @UserAgent() userAgent: string, @Ip() ip: string) {
    return this.authService.register({
      ...body,
      userAgent,
      ip
    })
  }

  @Post('send-otp')
  @IsPublic()
  @ZodSerializerDto(MessageResDTO)
  @Throttle({ short: { limit: 3, ttl: 60000 }, long: { limit: 10, ttl: 3600000 } })
  sendOTP(@Body() body: SendOTPBodyDTO) {
    return this.authService.sendOTP(body)
  }

  @Post('verify-code')
  @IsPublic()
  @ZodSerializerDto(VerifyCodeResDTO)
  @Throttle({ short: { limit: 5, ttl: 10000 }, long: { limit: 30, ttl: 60000 } })
  verifyCode(@Body() body: VerifyCodeBodyDTO, @UserAgent() userAgent: string, @Ip() ip: string) {
    return this.authService.verifyCode({
      ...body,
      userAgent,
      ip
    })
  }

  @Post('login')
  @IsPublic()
  @HttpCode(HttpStatus.OK)
  @UseZodSchemas(
    { schema: UserProfileResSchema, predicate: hasProperty('userId') },
    { schema: LoginSessionResSchema, predicate: hasProperty('otpToken') }
  )
  @Throttle({ short: { limit: 5, ttl: 60000 }, medium: { limit: 20, ttl: 300000 } })
  login(
    @Body() body: LoginBodyDTO,
    @UserAgent() userAgent: string,
    @Ip() ip: string,
    @Res({ passthrough: true }) res: Response
  ) {
    return this.authService.login(
      {
        ...body,
        userAgent,
        ip
      },
      res
    )
  }

  @Post('refresh-token')
  @IsPublic()
  @HttpCode(HttpStatus.OK)
  @ZodSerializerDto(RefreshTokenSuccessResDTO)
  @Throttle({ medium: { limit: 10, ttl: 60000 } })
  refreshToken(
    @Body() _: RefreshTokenBodyDTO,
    @UserAgent() userAgent: string,
    @Ip() ip: string,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response
  ) {
    return this.authService.refreshToken(
      {
        userAgent,
        ip
      },
      req,
      res
    )
  }

  @Post('logout')
  @HttpCode(HttpStatus.OK)
  @ZodSerializerDto(MessageResDTO)
  @Throttle({ short: { limit: 5, ttl: 10000 } })
  logout(@Body() _: LogoutBodyDTO, @Req() req: Request, @Res({ passthrough: true }) res: Response) {
    const logger = new Logger('AuthController')

    const cookieToken = req.cookies?.[CookieNames.REFRESH_TOKEN]
    if (cookieToken) {
      logger.log('Tìm thấy refreshToken trong cookie, sẽ sử dụng để đăng xuất')
    } else {
      logger.log('Không tìm thấy refreshToken trong cookie, sẽ chỉ xóa cookie hiện tại')
    }

    return this.authService.logout(req, res)
  }

  @Get('google-link')
  @IsPublic()
  @ZodSerializerDto(GetAuthorizationUrlResDTO)
  @SkipThrottle()
  getAuthorizationUrl(@UserAgent() userAgent: string, @Ip() ip: string, @Query('rememberMe') _rememberMe?: string) {
    return this.googleService.getAuthorizationUrl({
      userAgent,
      ip
    })
  }

  @Get('google/callback')
  @IsPublic()
  @SkipThrottle()
  async googleCallback(
    @Query('code') code: string,
    @Query('state') state: string,
    @Res() res: Response,
    @UserAgent() userAgent: string,
    @Ip() ip: string
  ) {
    try {
      if (!code) {
        return res.redirect(
          `${envConfig.GOOGLE_CLIENT_REDIRECT_URI}?error=invalid_request&errorMessage=${encodeURIComponent('Authorization code is missing')}`
        )
      }

      const data = await this.googleService.googleCallback({
        code,
        state,
        userAgent,
        ip
      })

      // Nếu googleCallback trả về loginSessionToken, nghĩa là cần 2FA
      if ('loginSessionToken' in data && data.loginSessionToken) {
        const queryParams = new URLSearchParams({
          twoFactorRequired: 'true',
          loginSessionToken: data.loginSessionToken,
          twoFactorMethod: data.twoFactorMethod as string
        })
        if (data.isGoogleAuth) {
          queryParams.set('source', 'google')
        }
        return res.redirect(`${envConfig.GOOGLE_CLIENT_REDIRECT_URI}?${queryParams.toString()}`)
      }

      // Nếu không cần 2FA, data sẽ chứa accessToken và refreshToken
      if ('accessToken' in data && data.accessToken && 'refreshToken' in data && data.refreshToken) {
        this.tokenService.setTokenCookies(res, data.accessToken, data.refreshToken)
        return res.redirect(
          `${envConfig.GOOGLE_CLIENT_REDIRECT_URI}?success=true&name=${encodeURIComponent(data.name || '')}&email=${encodeURIComponent(data.email || '')}`
        )
      }

      // Trường hợp không mong muốn
      this.logger.error('[AuthController googleCallback] Unexpected data structure from GoogleService', data)
      return res.redirect(
        `${envConfig.GOOGLE_CLIENT_REDIRECT_URI}?error=internal_error&errorMessage=${encodeURIComponent('Lỗi không xác định từ máy chủ.')}`
      )
    } catch (error) {
      console.error('Google OAuth callback error:', error)

      const errorCode = error.code || 'auth_error'
      const message =
        error instanceof Error
          ? encodeURIComponent(error.message)
          : encodeURIComponent('Đã xảy ra lỗi khi đăng nhập bằng Google, vui lòng thử lại bằng cách khác')

      return res.redirect(`${envConfig.GOOGLE_CLIENT_REDIRECT_URI}?error=${errorCode}&errorMessage=${message}`)
    }
  }

  @Post('reset-password')
  @IsPublic()
  @ZodSerializerDto(MessageResDTO)
  @Throttle({ short: { limit: 3, ttl: 60000 }, long: { limit: 10, ttl: 3600000 } })
  resetPassword(@Body() body: ResetPasswordBodyDTO, @UserAgent() userAgent: string, @Ip() ip: string) {
    return this.authService.resetPassword({
      ...body,
      userAgent,
      ip
    })
  }

  @Post('2fa/setup')
  @ZodSerializerDto(TwoFactorSetupResDTO)
  @Throttle({ short: { limit: 3, ttl: 60000 } })
  setupTwoFactorAuth(@Body() _: EmptyBodyDTO, @ActiveUser('userId') userId: number) {
    return this.authService.setupTwoFactorAuth(userId)
  }

  @Post('2fa/confirm-setup')
  @ZodSerializerDto(TwoFactorConfirmSetupResDTO)
  @Throttle({ short: { limit: 3, ttl: 60000 } })
  confirmTwoFactorSetup(@Body() body: TwoFactorConfirmSetupBodyDTO, @ActiveUser('userId') userId: number) {
    return this.authService.confirmTwoFactorSetup(userId, body.setupToken, body.totpCode)
  }

  @Post('2fa/disable')
  @ZodSerializerDto(MessageResDTO)
  @Throttle({ short: { limit: 3, ttl: 60000 } })
  disableTwoFactorAuth(@Body() body: DisableTwoFactorBodyDTO, @ActiveUser('userId') userId: number) {
    return this.authService.disableTwoFactorAuth({
      ...body,
      userId
    })
  }

  @Post('2fa/verify')
  @IsPublic()
  @HttpCode(HttpStatus.OK)
  @ZodSerializerDto(UserProfileResSchema)
  @Throttle({ short: { limit: 5, ttl: 60000 } })
  verifyTwoFactor(
    @Body() body: TwoFactorVerifyBodyDTO,
    @UserAgent() userAgent: string,
    @Ip() ip: string,
    @Res({ passthrough: true }) res: Response
  ) {
    return this.authService.verifyTwoFactor(
      {
        ...body,
        userAgent,
        ip
      },
      res
    )
  }

  @Post('trust-device')
  @HttpCode(HttpStatus.OK)
  @ZodSerializerDto(MessageResDTO)
  @Throttle({ short: { limit: 5, ttl: 60000 } })
  trustDevice(
    @ActiveUser() activeUser: AccessTokenPayload,
    @Body() _body: TrustDeviceBodyDTO,
    @Ip() ip: string,
    @UserAgent() userAgent: string
  ) {
    return this.authService.trustDevice(activeUser, ip, userAgent)
  }

  @Post('remember-me')
  @HttpCode(HttpStatus.OK)
  @ZodSerializerDto(MessageResDTO)
  @Throttle({ short: { limit: 5, ttl: 60000 } })
  setRememberMe(
    @ActiveUser() activeUser: AccessTokenPayload,
    @Body() body: RememberMeBodyDTO,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
    @Ip() ip: string,
    @UserAgent() userAgent: string
  ) {
    return this.authService.setRememberMe(activeUser, body.rememberMe, req, res, ip, userAgent)
  }

  @Post('logout-all')
  @HttpCode(HttpStatus.OK)
  @ZodSerializerDto(MessageResDTO)
  @Throttle({ short: { limit: 3, ttl: 60000 } }) // Can adjust throttling as needed
  logoutFromAllDevices(
    @ActiveUser() activeUser: AccessTokenPayload,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
    @Ip() ip: string,
    @UserAgent() userAgent: string
  ) {
    return this.authService.logoutFromAllDevices(activeUser, ip, userAgent, req, res)
  }
}
