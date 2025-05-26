import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Ip,
  Post,
  Query,
  Req,
  Res,
  Logger,
  Param,
  Patch,
  Delete,
  UseGuards
} from '@nestjs/common'
import { Response, Request } from 'express'
import { ZodSerializerDto } from 'nestjs-zod'
import {
  DisableTwoFactorBodyDTO,
  GetAuthorizationUrlResDTO,
  LoginBodyDTO,
  LogoutBodyDTO,
  RefreshTokenBodyDTO,
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
  RememberMeBodyDTO,
  RefreshTokenSuccessResDTO
} from 'src/routes/auth/auth.dto'
import {
  GetActiveSessionsResDTO,
  RevokeSessionParamsDTO,
  GetDevicesResDTO,
  DeviceIdParamsDTO,
  UpdateDeviceNameBodyDTO,
  TrustDeviceBodyDTO as SessionTrustDeviceBodyDTO,
  UntrustDeviceBodyDTO as SessionUntrustDeviceBodyDTO
} from './dtos/session-management.dto'
import { UserProfileResSchema, LoginSessionResSchema } from './auth.model'
import { UseZodSchemas, hasProperty } from 'src/shared/decorators/use-zod-schema.decorator'

import { AuthService } from 'src/routes/auth/auth.service'
import { GoogleService } from 'src/routes/auth/google.service'
import envConfig from 'src/shared/config'
import { ActiveUser } from './decorators/active-user.decorator'
import { IsPublic } from './decorators/auth.decorator'
import { UserAgent } from 'src/shared/decorators/user-agent.decorator'
import { EmptyBodyDTO } from 'src/shared/dtos/request.dto'
import { MessageResDTO } from 'src/shared/dtos/response.dto'
import { TokenService } from 'src/routes/auth/providers/token.service'
import { SkipThrottle, Throttle } from '@nestjs/throttler'
import { CookieNames } from 'src/shared/constants/auth.constant'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'
import { I18nContext } from 'nestjs-i18n'
import { I18nService } from 'nestjs-i18n'
import { SessionManagementService } from 'src/routes/auth/services/session-management.service'
import { AccessTokenGuard } from './guards/access-token.guard'
import { RolesGuard } from './guards/roles.guard'

@Controller('auth')
export class AuthController {
  private readonly logger = new Logger(AuthController.name)

  constructor(
    private readonly authService: AuthService,
    private readonly googleService: GoogleService,
    private readonly tokenService: TokenService,
    private readonly i18nService: I18nService,
    private readonly sessionManagementService: SessionManagementService
  ) {}

  @Post('register')
  @IsPublic()
  @ZodSerializerDto(RegisterResDTO)
  // @Throttle({ short: { limit: 5, ttl: 10000 }, long: { limit: 20, ttl: 60000 } })
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
  // @Throttle({ short: { limit: 3, ttl: 60000 }, long: { limit: 10, ttl: 3600000 } })
  sendOTP(@Body() body: SendOTPBodyDTO) {
    return this.authService.sendOTP(body)
  }

  @Post('verify-code')
  @IsPublic()
  @ZodSerializerDto(VerifyCodeResDTO)
  // @Throttle({ short: { limit: 5, ttl: 10000 }, long: { limit: 30, ttl: 60000 } })
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
  // @Throttle({ short: { limit: 5, ttl: 60000 }, medium: { limit: 20, ttl: 300000 } })
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
  // @Throttle({ medium: { limit: 10, ttl: 60000 } })
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
  // @Throttle({ short: { limit: 5, ttl: 10000 } })
  logout(@Body() _: LogoutBodyDTO, @Req() req: Request, @Res({ passthrough: true }) res: Response) {
    const cookieToken = req.cookies?.[CookieNames.REFRESH_TOKEN]
    if (cookieToken) {
      this.logger.log('Refresh token found in cookie, will be used for logout')
    } else {
      this.logger.log('Refresh token not found in cookie, will only clear current cookies')
    }

    return this.authService.logout(req, res)
  }

  @Get('google-link')
  @IsPublic()
  @ZodSerializerDto(GetAuthorizationUrlResDTO)
  @SkipThrottle()
  getAuthorizationUrl(@UserAgent() userAgent: string, @Ip() ip: string) {
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
    const currentLang = I18nContext.current()?.lang
    try {
      if (!code) {
        const missingCodeMessage = await this.i18nService.translate('error.Error.Auth.Google.MissingCode', {
          lang: currentLang
        })
        return res.redirect(
          `${envConfig.GOOGLE_CLIENT_REDIRECT_URI}?error=invalid_request&errorMessage=${encodeURIComponent(missingCodeMessage)}`
        )
      }

      const data = await this.googleService.googleCallback({
        code,
        state,
        userAgent,
        ip
      })

      if (data.redirectToError) {
        this.logger.error(`[AuthController googleCallback] Error from GoogleService: ${data.errorMessage}`)
        return res.redirect(
          `${envConfig.GOOGLE_CLIENT_REDIRECT_URI}?error=${data.errorCode}&errorMessage=${encodeURIComponent(data.errorMessage)}`
        )
      }

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

      if (data && data.accessToken) {
        this.tokenService.setTokenCookies(res, data.accessToken, data.refreshTokenJti, data.maxAgeForRefreshTokenCookie)
        res.status(HttpStatus.OK).json({
          message: 'Google login successful, tokens set in cookies.',
          user: data.user
        })
      } else {
        const unknownErrorMessage = await this.i18nService.translate('error.Error.Auth.Google.CallbackErrorGeneric', {
          lang: currentLang
        })
        this.logger.error('[AuthController googleCallback] Unexpected data structure from GoogleService', data)
        return res.redirect(
          `${envConfig.GOOGLE_CLIENT_REDIRECT_URI}?error=internal_error&errorMessage=${encodeURIComponent(unknownErrorMessage)}`
        )
      }
    } catch (error) {
      this.logger.error('Google OAuth callback error in controller:', error.stack, error.message)
      const genericErrorMessage = await this.i18nService.translate('error.Error.Auth.Google.CallbackErrorGeneric', {
        lang: currentLang
      })
      const errorCode = error.code || 'auth_error_controller'
      const message =
        error instanceof Error ? encodeURIComponent(error.message) : encodeURIComponent(genericErrorMessage)

      return res.redirect(`${envConfig.GOOGLE_CLIENT_REDIRECT_URI}?error=${errorCode}&errorMessage=${message}`)
    }
  }

  @Post('reset-password')
  @IsPublic()
  @ZodSerializerDto(MessageResDTO)
  // @Throttle({ short: { limit: 3, ttl: 60000 }, long: { limit: 10, ttl: 3600000 } })
  resetPassword(@Body() body: ResetPasswordBodyDTO, @UserAgent() userAgent: string, @Ip() ip: string) {
    return this.authService.resetPassword({
      ...body,
      userAgent,
      ip
    })
  }

  @Post('2fa/setup')
  @ZodSerializerDto(TwoFactorSetupResDTO)
  // @Throttle({ short: { limit: 3, ttl: 60000 } })
  setupTwoFactorAuth(@Body() _: EmptyBodyDTO, @ActiveUser('userId') userId: number) {
    return this.authService.setupTwoFactorAuth(userId)
  }

  @Post('2fa/confirm-setup')
  @ZodSerializerDto(TwoFactorConfirmSetupResDTO)
  // @Throttle({ short: { limit: 3, ttl: 60000 } })
  confirmTwoFactorSetup(@Body() body: TwoFactorConfirmSetupBodyDTO, @ActiveUser('userId') userId: number) {
    return this.authService.confirmTwoFactorSetup(userId, body.setupToken, body.totpCode)
  }

  @Post('2fa/disable')
  @ZodSerializerDto(MessageResDTO)
  // @Throttle({ short: { limit: 3, ttl: 60000 } })
  disableTwoFactorAuth(@Body() body: DisableTwoFactorBodyDTO, @ActiveUser('userId') userId: number) {
    return this.authService.disableTwoFactorAuth({
      ...body,
      userId
    })
  }

  @Post('login/verify')
  @IsPublic()
  @HttpCode(HttpStatus.OK)
  @ZodSerializerDto(UserProfileResSchema)
  // @Throttle({ short: { limit: 5, ttl: 60000 } })
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

  @Post('remember-me')
  @HttpCode(HttpStatus.OK)
  @ZodSerializerDto(MessageResDTO)
  // @Throttle({ short: { limit: 5, ttl: 60000 } })
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
  // @Throttle({ short: { limit: 3, ttl: 60000 } })
  logoutFromAllDevices(
    @ActiveUser() activeUser: AccessTokenPayload,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
    @Ip() ip: string,
    @UserAgent() userAgent: string
  ) {
    return this.authService.logoutFromAllDevices(activeUser, ip, userAgent, req, res)
  }

  @Get('sessions')
  @UseGuards(AccessTokenGuard, RolesGuard)
  @ZodSerializerDto(GetActiveSessionsResDTO)
  async getActiveSessions(@ActiveUser() activeUser: AccessTokenPayload) {
    this.logger.debug(
      `User ${activeUser.userId} fetching active sessions. Current session: ${activeUser.sessionId}, current device: ${activeUser.deviceId}`
    )
    const rawSessions = await this.sessionManagementService.getActiveSessions(
      activeUser.userId,
      activeUser.sessionId,
      activeUser.deviceId
    )
    this.logger.debug(
      `Raw active sessions from service - IsArray: ${Array.isArray(rawSessions)}, Value: ${JSON.stringify(rawSessions, null, 2)}`
    )
    return rawSessions
  }

  @Delete('sessions/:sessionId')
  @HttpCode(HttpStatus.OK)
  @ZodSerializerDto(MessageResDTO)
  revokeSession(@ActiveUser() activeUser: AccessTokenPayload, @Param() params: RevokeSessionParamsDTO) {
    return this.sessionManagementService.revokeSession(activeUser.userId, params.sessionId, activeUser.sessionId)
  }

  @Get('devices')
  @UseGuards(AccessTokenGuard, RolesGuard)
  @ZodSerializerDto(GetDevicesResDTO)
  async getManagedDevices(@ActiveUser('userId') userId: number) {
    this.logger.debug(`User ${userId} fetching managed devices.`)
    const rawDevices = await this.sessionManagementService.getManagedDevices(userId)
    this.logger.debug(
      `Raw managed devices from service - IsArray: ${Array.isArray(rawDevices)}, Value: ${JSON.stringify(rawDevices, null, 2)}`
    )
    return rawDevices
  }

  @Patch('devices/:deviceId/name')
  @HttpCode(HttpStatus.OK)
  @ZodSerializerDto(MessageResDTO)
  updateDeviceName(
    @ActiveUser('userId') userId: number,
    @Param() params: DeviceIdParamsDTO,
    @Body() body: UpdateDeviceNameBodyDTO
  ) {
    return this.sessionManagementService.updateDeviceName(userId, params.deviceId, body.name)
  }

  @Post('devices/:deviceId/trust')
  @HttpCode(HttpStatus.OK)
  @ZodSerializerDto(MessageResDTO)
  trustManagedDevice(
    @ActiveUser('userId') userId: number,
    @Param() params: DeviceIdParamsDTO,
    @Body() _body: SessionTrustDeviceBodyDTO
  ) {
    return this.sessionManagementService.trustManagedDevice(userId, params.deviceId)
  }

  @Post('devices/:deviceId/untrust')
  @HttpCode(HttpStatus.OK)
  @ZodSerializerDto(MessageResDTO)
  untrustManagedDevice(
    @ActiveUser('userId') userId: number,
    @Param() params: DeviceIdParamsDTO,
    @Body() _body: SessionUntrustDeviceBodyDTO
  ) {
    return this.sessionManagementService.untrustManagedDevice(userId, params.deviceId)
  }

  @Post('devices/:deviceId/logout')
  @HttpCode(HttpStatus.OK)
  @ZodSerializerDto(MessageResDTO)
  logoutFromManagedDevice(
    @ActiveUser() activeUser: AccessTokenPayload,
    @Param() params: DeviceIdParamsDTO,
    @Ip() ip: string,
    @UserAgent() userAgent: string
  ) {
    return this.sessionManagementService.logoutFromManagedDevice(activeUser.userId, params.deviceId, {
      userId: activeUser.userId,
      ipAddress: ip,
      userAgent: userAgent
    })
  }
}
