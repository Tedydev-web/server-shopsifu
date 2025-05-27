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
  UseGuards,
  ParseIntPipe
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
  RefreshTokenSuccessResDTO,
  UserProfileResDTO
} from 'src/routes/auth/auth.dto'
import {
  // GetActiveSessionsResDTO, // Keep for now if other parts of the app use it, otherwise remove
  RevokeSessionParamsDTO,
  // GetDevicesResDTO, // Removed as the endpoint is being phased out
  DeviceIdParamsDTO,
  UpdateDeviceNameBodyDTO,
  TrustDeviceBodyDTO as SessionTrustDeviceBodyDTO,
  UntrustDeviceBodyDTO as SessionUntrustDeviceBodyDTO,
  RevokeSessionsBodyDTO,
  GetSessionsGroupedByDeviceResDTO,
  GetSessionsByDeviceQueryDTO,
  DeviceWithSessionsSchema,
  GetSessionsGroupedByDeviceResSchema,
  DeviceInfoSchema
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
import { SkipThrottle } from '@nestjs/throttler'
import { CookieNames } from 'src/shared/constants/auth.constant'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'
import { I18nContext } from 'nestjs-i18n'
import { I18nService } from 'nestjs-i18n'
import { SessionManagementService } from 'src/routes/auth/services/session-management.service'
import { AccessTokenGuard } from './guards/access-token.guard'
import { RolesGuard } from './guards/roles.guard'
import { PaginatedResponseType } from 'src/shared/models/pagination.model'
import { ActiveSessionSchema } from './dtos/session-management.dto'
import { z } from 'zod'
import { AuthType } from 'src/shared/constants/auth.constant'
import { AuditLog } from 'src/shared/decorators/audit-log.decorator'
import { Auth } from './decorators/auth.decorator'
import { OtpService } from './providers/otp.service'
import { TypeOfVerificationCode } from './constants/auth.constants'
import { v4 as uuidv4 } from 'uuid'
import ms from 'ms'
import { REDIS_KEY_PREFIX } from 'src/shared/constants/redis.constants'
import { RedisService } from 'src/shared/providers/redis/redis.service'
import { JwtService } from '@nestjs/jwt'
import { GoogleCallbackSuccessResult } from './google.service'
import { AuthenticationService } from './services/authentication.service'
import { ApiException } from 'src/shared/exceptions/api.exception'
import { Buffer } from 'buffer'

@Controller('auth')
export class AuthController {
  private readonly logger = new Logger(AuthController.name)

  constructor(
    private readonly authService: AuthService,
    private readonly googleService: GoogleService,
    private readonly tokenService: TokenService,
    private readonly i18nService: I18nService,
    private readonly sessionManagementService: SessionManagementService,
    private readonly otpService: OtpService,
    private readonly redisService: RedisService,
    private readonly jwtService: JwtService,
    private readonly authenticationService: AuthenticationService
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
  getAuthorizationUrl(@UserAgent() userAgent: string, @Ip() ip: string, @Res({ passthrough: true }) res: Response) {
    const { url, nonce } = this.googleService.getAuthorizationUrl({
      userAgent,
      ip
    })

    const nonceCookieConfig = envConfig.cookie.nonce
    const isDevelopment = envConfig.NODE_ENV === 'development'

    res.cookie(CookieNames.OAUTH_NONCE, nonce, {
      path: nonceCookieConfig.path,
      domain: nonceCookieConfig.domain,
      maxAge: nonceCookieConfig.maxAge,
      httpOnly: nonceCookieConfig.httpOnly,
      secure: nonceCookieConfig.secure,
      sameSite: nonceCookieConfig.sameSite
    })

    return { url }
  }

  @Get('google/callback')
  @IsPublic()
  @SkipThrottle()
  @ZodSerializerDto(UserProfileResSchema)
  async googleCallback(
    @Query('code') code: string,
    @Query('state') stateFromGoogle: string,
    @Res({ passthrough: true }) res: Response,
    @Req() req: Request,
    @UserAgent() userAgent: string,
    @Ip() ip: string
  ) {
    this.logger.log('[GoogleCallback] Received callback from Google.')
    this.logger.debug(`[GoogleCallback] Request Cookies: ${JSON.stringify(req.cookies)}`)
    this.logger.debug(`[GoogleCallback] Request Cookie Header: ${req.headers.cookie}`)
    this.logger.debug(`[GoogleCallback] Request Origin Header: ${req.headers.origin}`)
    this.logger.debug(`[GoogleCallback] Request Referer Header: ${req.headers.referer}`)
    this.logger.debug(`[GoogleCallback] Full Request URL: ${req.protocol}://${req.get('host')}${req.originalUrl}`)

    const currentLang = I18nContext.current()?.lang
    const nonceFromCookie = req.cookies?.[CookieNames.OAUTH_NONCE]
    const nonceCookieConfig = envConfig.cookie.nonce

    let nonceFromStateParam: string | undefined
    let rememberMeFromState: boolean = false

    if (stateFromGoogle) {
      try {
        const decodedStateObj = JSON.parse(Buffer.from(stateFromGoogle, 'base64').toString('utf-8'))
        nonceFromStateParam = decodedStateObj?.nonce
        userAgent = decodedStateObj?.userAgent || userAgent
        ip = decodedStateObj?.ip || ip
        if (typeof decodedStateObj?.rememberMe === 'boolean') {
          rememberMeFromState = decodedStateObj.rememberMe
        }
      } catch (e) {
        this.logger.error('[GoogleCallback] Failed to parse state parameter from Google.', e)
        const genericErrorMessage = await this.i18nService.translate('error.Error.Auth.Google.CallbackErrorGeneric', {
          lang: currentLang
        })
        if (res) {
          res.clearCookie(CookieNames.OAUTH_NONCE, {
            path: nonceCookieConfig.path,
            domain: nonceCookieConfig.domain,
            httpOnly: nonceCookieConfig.httpOnly,
            secure: nonceCookieConfig.secure,
            sameSite: nonceCookieConfig.sameSite
          })
        }
        return res.redirect(
          `${envConfig.FRONTEND_URL}/auth/callback/google?error=invalid_state&errorMessage=${encodeURIComponent(genericErrorMessage)}`
        )
      }
    }

    if (!nonceFromCookie || !nonceFromStateParam || nonceFromCookie !== nonceFromStateParam) {
      this.logger.error(
        `[GoogleCallback] Nonce mismatch or missing. Cookie: ${nonceFromCookie ? 'present' : 'missing'}, StateParam: ${nonceFromStateParam ? 'present' : 'missing'}. CSRF attempt?`
      )
      const csrfErrorMessage = await this.i18nService.translate('error.Error.Auth.Google.CsrfOrStateMismatch', {
        lang: currentLang,
        defaultValue: 'Login with Google failed due to a security check. Please try again.'
      })
      if (res) {
        res.clearCookie(CookieNames.OAUTH_NONCE, {
          path: nonceCookieConfig.path,
          domain: nonceCookieConfig.domain,
          httpOnly: nonceCookieConfig.httpOnly,
          secure: nonceCookieConfig.secure,
          sameSite: nonceCookieConfig.sameSite
        })
      }
      return res.redirect(
        `${envConfig.FRONTEND_URL}/auth/callback/google?error=csrf_error&errorMessage=${encodeURIComponent(csrfErrorMessage)}`
      )
    }

    if (!code) {
      const missingCodeMessage = await this.i18nService.translate('error.Error.Auth.Google.MissingCode', {
        lang: currentLang
      })
      if (res) {
        res.clearCookie(CookieNames.OAUTH_NONCE, {
          path: nonceCookieConfig.path,
          domain: nonceCookieConfig.domain,
          httpOnly: nonceCookieConfig.httpOnly,
          secure: nonceCookieConfig.secure,
          sameSite: nonceCookieConfig.sameSite
        })
      }
      return res.redirect(
        `${envConfig.FRONTEND_URL}/auth/callback/google?error=missing_code&errorMessage=${encodeURIComponent(missingCodeMessage)}`
      )
    }

    try {
      const googleAuthResultFromService = await this.googleService.googleCallback({
        code,
        state: stateFromGoogle,
        userAgent,
        ip
      })

      if ('redirectToError' in googleAuthResultFromService && googleAuthResultFromService.redirectToError === true) {
        this.logger.error(
          `[AuthController googleCallback] Error from GoogleService: ${googleAuthResultFromService.errorMessage}`
        )
        if (res) {
          res.clearCookie(CookieNames.OAUTH_NONCE, {
            path: nonceCookieConfig.path,
            domain: nonceCookieConfig.domain,
            httpOnly: nonceCookieConfig.httpOnly,
            secure: nonceCookieConfig.secure,
            sameSite: nonceCookieConfig.sameSite
          })
        }
        return res.redirect(
          `${envConfig.FRONTEND_URL}/auth/callback/google?error=${googleAuthResultFromService.errorCode}&errorMessage=${encodeURIComponent(googleAuthResultFromService.errorMessage)}`
        )
      }

      const googleAuthResult = googleAuthResultFromService as GoogleCallbackSuccessResult
      const { user, device, requiresTwoFactorAuth, requiresUntrustedDeviceVerification, twoFactorMethod } =
        googleAuthResult

      const sltCookieConfig = envConfig.cookie.sltToken

      if (requiresTwoFactorAuth && user.twoFactorMethod) {
        this.logger.log(`[GoogleCallback] User ${user.id} requires 2FA (${user.twoFactorMethod}). Initiating SLT flow.`)
        const sltJwt = await this.otpService.initiateOtpWithSltCookie({
          email: user.email,
          userId: user.id,
          deviceId: device.id,
          ipAddress: ip,
          userAgent: userAgent,
          purpose: TypeOfVerificationCode.LOGIN_2FA,
          metadata: {
            isGoogleAuth: true,
            rememberMe: rememberMeFromState,
            twoFactorMethod: user.twoFactorMethod
          }
        })
        res.cookie(sltCookieConfig.name, sltJwt, {
          path: sltCookieConfig.path,
          domain: sltCookieConfig.domain,
          maxAge: sltCookieConfig.maxAge,
          httpOnly: sltCookieConfig.httpOnly,
          secure: sltCookieConfig.secure,
          sameSite: sltCookieConfig.sameSite as 'lax' | 'strict' | 'none' | boolean
        })
        const queryParams = new URLSearchParams({
          twoFactorRequired: 'true',
          twoFactorMethod: user.twoFactorMethod,
          source: 'google'
        })
        if (res) {
          res.clearCookie(CookieNames.OAUTH_NONCE, {
            path: nonceCookieConfig.path,
            domain: nonceCookieConfig.domain,
            httpOnly: nonceCookieConfig.httpOnly,
            secure: nonceCookieConfig.secure,
            sameSite: nonceCookieConfig.sameSite
          })
        }
        return res.redirect(`${envConfig.FRONTEND_URL}/login/verify-2fa?${queryParams.toString()}`)
      }

      if (requiresUntrustedDeviceVerification) {
        this.logger.log(`[GoogleCallback] User ${user.id} requires untrusted device verification. Initiating SLT flow.`)
        const sltJwt = await this.otpService.initiateOtpWithSltCookie({
          email: user.email,
          userId: user.id,
          deviceId: device.id,
          ipAddress: ip,
          userAgent: userAgent,
          purpose: TypeOfVerificationCode.LOGIN_UNTRUSTED_DEVICE_OTP,
          metadata: {
            isGoogleAuth: true,
            rememberMe: rememberMeFromState
          }
        })
        res.cookie(sltCookieConfig.name, sltJwt, {
          path: sltCookieConfig.path,
          domain: sltCookieConfig.domain,
          maxAge: sltCookieConfig.maxAge,
          httpOnly: sltCookieConfig.httpOnly,
          secure: sltCookieConfig.secure,
          sameSite: sltCookieConfig.sameSite as 'lax' | 'strict' | 'none' | boolean
        })
        const queryParams = new URLSearchParams({
          deviceVerificationRequired: 'true',
          source: 'google'
        })
        if (res) {
          res.clearCookie(CookieNames.OAUTH_NONCE, {
            path: nonceCookieConfig.path,
            domain: nonceCookieConfig.domain,
            httpOnly: nonceCookieConfig.httpOnly,
            secure: nonceCookieConfig.secure,
            sameSite: nonceCookieConfig.sameSite
          })
        }
        return res.redirect(`${envConfig.FRONTEND_URL}/login/verify-device?${queryParams.toString()}`)
      }

      this.logger.log(
        `[GoogleCallback] User ${user.id} passed OAuth security checks. Finalizing login directly via Google. Device ID: ${device.id}. Remember Me: ${rememberMeFromState}`
      )

      const loginResult = await this.authenticationService.finalizeOauthLogin(
        user,
        device,
        rememberMeFromState,
        ip,
        userAgent,
        'google-oauth',
        res
      )

      const successRedirectUrl = `${envConfig.FRONTEND_URL}` // Or a more specific success page like /dashboard or /login/oauth-success
      this.logger.log(
        `[GoogleCallback] Successful login for user ${user.id} via google-oauth. Redirecting to ${successRedirectUrl}`
      )
      if (res) {
        res.redirect(successRedirectUrl)
        res.clearCookie(CookieNames.OAUTH_NONCE, {
          path: nonceCookieConfig.path,
          domain: nonceCookieConfig.domain,
          httpOnly: nonceCookieConfig.httpOnly,
          secure: nonceCookieConfig.secure,
          sameSite: nonceCookieConfig.sameSite
        })
        return
      } else {
        this.logger.warn(
          `[GoogleCallback] Response object not available for redirect. Returning login result as JSON for user ${user.id}.`
        )
        return {
          userId: loginResult.userId,
          email: loginResult.email,
          name: loginResult.name,
          role: loginResult.role,
          isDeviceTrustedInSession: loginResult.isDeviceTrustedInSession,
          currentDeviceId: loginResult.currentDeviceId
        }
      }
    } catch (error) {
      this.logger.error('Google OAuth callback error in controller:', error.stack, error.message)
      const genericErrorMessage = await this.i18nService.translate('error.Error.Auth.Google.CallbackErrorGeneric', {
        lang: currentLang
      })

      let determinedErrorCode = 'auth_error_controller_final'
      if (
        typeof error === 'object' &&
        error !== null &&
        'code' in error &&
        typeof (error as { code?: unknown }).code === 'string'
      ) {
        determinedErrorCode = (error as { code: string }).code
      } else if (error instanceof ApiException) {
        determinedErrorCode = error.getStatus().toString()
      }

      const messageToEncode = error instanceof Error ? error.message : genericErrorMessage
      const message = encodeURIComponent(messageToEncode)

      if (res) {
        res.clearCookie(CookieNames.OAUTH_NONCE, {
          path: nonceCookieConfig.path,
          domain: nonceCookieConfig.domain,
          httpOnly: nonceCookieConfig.httpOnly,
          secure: nonceCookieConfig.secure,
          sameSite: nonceCookieConfig.sameSite
        })
      }
      return res.redirect(
        `${envConfig.FRONTEND_URL}/auth/callback/google?error=${determinedErrorCode}&errorMessage=${message}`
      )
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
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response
  ) {
    const sltCookie = req.cookies?.[CookieNames.SLT_TOKEN]
    return this.authService.verifyTwoFactor(
      {
        ...body,
        userAgent,
        ip,
        sltCookie
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
  @ZodSerializerDto(GetSessionsGroupedByDeviceResDTO)
  async getActiveSessions(
    @ActiveUser() activeUser: AccessTokenPayload,
    @Query() query: GetSessionsByDeviceQueryDTO
  ): Promise<z.infer<typeof GetSessionsGroupedByDeviceResSchema>> {
    this.logger.debug(
      `User ${activeUser.userId} fetching active sessions (grouped by device). Current session: ${activeUser.sessionId}, current device: ${activeUser.deviceId}, query: ${JSON.stringify(query)}`
    )
    return this.sessionManagementService.getActiveSessions(
      activeUser.userId,
      activeUser.sessionId,
      activeUser.deviceId,
      query
    )
  }

  @Delete('sessions/:sessionId')
  @HttpCode(HttpStatus.OK)
  @ZodSerializerDto(MessageResDTO)
  revokeSession(@ActiveUser() activeUser: AccessTokenPayload, @Param() params: RevokeSessionParamsDTO) {
    return this.sessionManagementService.revokeSession(activeUser.userId, params.sessionId, activeUser.sessionId)
  }

  @Delete('sessions')
  @HttpCode(HttpStatus.OK)
  @ZodSerializerDto(MessageResDTO)
  revokeMultipleSessions(@ActiveUser() activeUser: AccessTokenPayload, @Body() body: RevokeSessionsBodyDTO) {
    return this.sessionManagementService.revokeMultipleSessions(activeUser.userId, activeUser.sessionId, body)
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
    @ActiveUser() activeUser: AccessTokenPayload,
    @Param() params: DeviceIdParamsDTO,
    @Body() _body: SessionUntrustDeviceBodyDTO
  ) {
    return this.sessionManagementService.untrustManagedDevice(activeUser.userId, params.deviceId, activeUser.sessionId)
  }

  @Post('sessions/current/trust-device')
  @HttpCode(HttpStatus.OK)
  @ZodSerializerDto(MessageResDTO)
  trustCurrentDevice(@ActiveUser() activeUser: AccessTokenPayload, @Body() _body: EmptyBodyDTO) {
    // activeUser.deviceId is the ID of the device record in the database
    return this.sessionManagementService.trustCurrentDevice(activeUser.userId, activeUser.deviceId)
  }
}
