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
  UsePipes
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
  UserProfileResDTO,
  ReverifyPasswordBodyType
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
  GetSessionsGroupedByDeviceResSchema
} from './dtos/session-management.dto'
import { UseZodSchemas, hasProperty } from 'src/shared/decorators/use-zod-schema.decorator'

import { AuthService } from 'src/routes/auth/auth.service'
import { GoogleService } from './google.service'
import envConfig from 'src/shared/config'
import { ActiveUser } from './decorators/active-user.decorator'
import { IsPublic } from './decorators/auth.decorator'
import { UserAgent } from 'src/shared/decorators/user-agent.decorator'
import { EmptyBodyDTO } from 'src/shared/dtos/request.dto'
import { MessageResDTO } from 'src/shared/dtos/response.dto'
import { TokenService } from 'src/routes/auth/providers/token.service'
import { SkipThrottle } from '@nestjs/throttler'
import { CookieNames, AuthType } from 'src/shared/constants/auth.constant'
import { AccessTokenPayload, PendingLinkTokenPayloadCreate } from 'src/shared/types/jwt.type'
import { I18nContext } from 'nestjs-i18n'
import { I18nService } from 'nestjs-i18n'
import { SessionManagementService } from 'src/routes/auth/services/session-management.service'
import { AccessTokenGuard } from './guards/access-token.guard'
import { RolesGuard } from './guards/roles.guard'
import { z } from 'zod'
import { Auth } from './decorators/auth.decorator'
import { OtpService } from './providers/otp.service'
import { TypeOfVerificationCode } from './constants/auth.constants'
import { RedisService } from 'src/shared/providers/redis/redis.service'
import { JwtService } from '@nestjs/jwt'
import { AuthenticationService } from './services/authentication.service'
import { ApiException } from 'src/shared/exceptions/api.exception'
import { Buffer } from 'buffer'
import { RevokeSessionsResDTO } from './dtos/session-management.dto'
import { AllowWithoutPasswordReverification } from './guards/password-reverification.guard'
import { SharedUserRepository } from './repositories/shared-user.repo'
import { LinkGoogleAccountReqDto, LinkGoogleAccountReqSchema } from './dtos/link-google-account.dto'
import { UserProfileResSchema, LoginSessionResSchema, GoogleAuthStateType } from './auth.model'
import { ZodValidationPipe } from 'nestjs-zod'
import { PendingLinkDetailsResSchema, PendingLinkDetailsResDto } from './dtos/pending-link-details.dto'
import { DeviceService } from './providers/device.service'

// Định nghĩa một type cục bộ cho cấu hình cookie PLT, chỉ chứa các trường cần thiết
interface PltCookieConfigType {
  name: string
  path?: string
  domain?: string
  maxAge: number // Bắt buộc khi set cookie
  httpOnly?: boolean
  secure?: boolean
  sameSite?: 'lax' | 'strict' | 'none' | boolean
}

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
    private readonly authenticationService: AuthenticationService,
    private readonly sharedUserRepository: SharedUserRepository,
    private readonly deviceService: DeviceService
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
    { schema: UserProfileResSchema, predicate: hasProperty('id') },
    { schema: LoginSessionResSchema, predicate: hasProperty('message') }
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
    return this.authService.logout(req, res)
  }

  @Get('google-link')
  @IsPublic()
  @ZodSerializerDto(GetAuthorizationUrlResDTO)
  @SkipThrottle()
  getAuthorizationUrl(
    @UserAgent() userAgent: string,
    @Ip() ip: string,
    @Res({ passthrough: true }) res: Response,
    @Query('flow') flow?: string, // 'profile_link'
    @ActiveUser() activeUser?: AccessTokenPayload // Optional active user
  ) {
    let stateObjectExtra: Record<string, any> = {}
    if (flow === 'profile_link' && activeUser?.userId) {
      stateObjectExtra = {
        flow: 'profile_link',
        userIdIfLinking: activeUser.userId
      }
      this.logger.log(`[getAuthorizationUrl] Profile linking flow initiated for user ${activeUser.userId}`)
    }

    const { url, nonce } = this.googleService.getAuthorizationUrl({
      userAgent,
      ip,
      ...stateObjectExtra // Truyền thêm thông tin vào state
    })

    const nonceCookieConfig = envConfig.cookie.nonce
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
    const currentLang = I18nContext.current()?.lang
    const nonceFromCookie = req.cookies?.[CookieNames.OAUTH_NONCE]
    const nonceCookieConfig = envConfig.cookie.nonce

    if (nonceFromCookie && nonceCookieConfig) {
      res.clearCookie(CookieNames.OAUTH_NONCE, {
        path: nonceCookieConfig.path,
        domain: nonceCookieConfig.domain,
        httpOnly: nonceCookieConfig.httpOnly,
        secure: nonceCookieConfig.secure,
        sameSite: nonceCookieConfig.sameSite as 'lax' | 'strict' | 'none' | boolean
      })
    }

    let nonceFromStateParam: string | undefined
    let rememberMeFromState: boolean = false

    if (stateFromGoogle) {
      try {
        const decodedStateObj = JSON.parse(
          Buffer.from(stateFromGoogle, 'base64').toString('utf-8')
        ) as GoogleAuthStateType & { nonce: string } // Ép kiểu đầy đủ
        nonceFromStateParam = decodedStateObj?.nonce
        // Ưu tiên userAgent, ip từ state nếu có
        userAgent = decodedStateObj?.userAgent || userAgent
        ip = decodedStateObj?.ip || ip
        if (typeof decodedStateObj?.rememberMe === 'boolean') {
          rememberMeFromState = decodedStateObj.rememberMe
        }

        // Kiểm tra Profile Linking Flow
        if (decodedStateObj?.flow === 'profile_link' && typeof decodedStateObj?.userIdIfLinking === 'number') {
          this.logger.log(
            `[GoogleCallback] Detected profile_link flow from state for user ID: ${decodedStateObj.userIdIfLinking}`
          )
          const googleTokens = await this.googleService.getGoogleTokens(code)
          if (!googleTokens || !googleTokens.id_token) {
            this.logger.error('[GoogleCallback-ProfileLink] Failed to get Google tokens or missing id_token.')
            return res.redirect(
              `${envConfig.FRONTEND_URL}/profile/settings?googleLinkStatus=error&errorCode=TOKEN_FETCH_FAILED`
            )
          }
          const googlePayload = await this.googleService.verifyGoogleIdToken(googleTokens.id_token)

          if (!googlePayload || !googlePayload.sub || !googlePayload.email) {
            this.logger.error('[GoogleCallback-ProfileLink] Invalid Google payload for profile link.')
            return res.redirect(
              `${envConfig.FRONTEND_URL}/profile/settings?googleLinkStatus=error&errorCode=INVALID_GOOGLE_PAYLOAD`
            )
          }

          try {
            const linkedUserProfile = await this.googleService.linkGoogleAccount(
              decodedStateObj.userIdIfLinking,
              googlePayload.sub,
              googlePayload.email,
              googlePayload.name,
              googlePayload.picture
            )
            this.logger.log(
              `[GoogleCallback-ProfileLink] Successfully linked Google account for user ${linkedUserProfile.id}. Redirecting to profile.`
            )
            return res.redirect(
              `${envConfig.FRONTEND_URL}/profile/settings?googleLinkStatus=success&userEmail=${encodeURIComponent(linkedUserProfile.email)}`
            )
          } catch (linkError) {
            this.logger.error('[GoogleCallback-ProfileLink] Error linking account:', linkError)
            let errorCode = 'LINK_FAILED'
            if (linkError instanceof ApiException) {
              errorCode = linkError.errorCode || errorCode
            }
            return res.redirect(
              `${envConfig.FRONTEND_URL}/profile/settings?googleLinkStatus=error&errorCode=${errorCode}&message=${encodeURIComponent(linkError.message)}`
            )
          }
        } // Kết thúc xử lý profile_link flow
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

      if ('redirectToError' in googleAuthResultFromService && googleAuthResultFromService.redirectToError) {
        this.logger.error(
          `[AuthController googleCallback] Error from GoogleService: ${googleAuthResultFromService.errorMessage}`
        )
        return res.redirect(
          `${envConfig.FRONTEND_URL}/auth/callback/google?error=${googleAuthResultFromService.errorCode}&errorMessage=${encodeURIComponent(googleAuthResultFromService.errorMessage)}`
        )
      } else if ('needsLinking' in googleAuthResultFromService && googleAuthResultFromService.needsLinking) {
        const linkResult = googleAuthResultFromService
        this.logger.log(
          `[AuthController googleCallback] Account ${linkResult.existingUserEmail} (ID: ${linkResult.existingUserId}) needs linking with Google ID ${linkResult.googleId}.`
        )

        const pltPayload: PendingLinkTokenPayloadCreate = {
          existingUserId: linkResult.existingUserId,
          googleId: linkResult.googleId,
          googleEmail: linkResult.googleEmail,
          googleName: linkResult.googleName,
          googleAvatar: linkResult.googleAvatar
        }
        const pendingLinkToken = this.tokenService.signPendingLinkToken(pltPayload)

        const pltCookieConfigFromEnv = (envConfig.cookie as Record<string, any>)?.oauthPendingLinkToken

        if (
          !pltCookieConfigFromEnv ||
          typeof pltCookieConfigFromEnv.name !== 'string' ||
          typeof pltCookieConfigFromEnv.maxAge !== 'number'
        ) {
          this.logger.error(
            '[AuthController googleCallback] OAUTH_PENDING_LINK_TOKEN cookie configuration is critically missing or incomplete in envConfig.'
          )
          throw new ApiException(
            HttpStatus.INTERNAL_SERVER_ERROR,
            'SERVER_CONFIG_ERROR',
            'Error.Server.ConfigError.MissingOAuthCookie'
          )
        }
        // Sử dụng type vừa định nghĩa
        const pltCookieConfig = pltCookieConfigFromEnv as Required<PltCookieConfigType>

        res.cookie(pltCookieConfig.name, pendingLinkToken, {
          path: pltCookieConfig.path || '/',
          domain: pltCookieConfig.domain,
          maxAge: pltCookieConfig.maxAge,
          httpOnly: pltCookieConfig.httpOnly !== undefined ? pltCookieConfig.httpOnly : true,
          secure: pltCookieConfig.secure !== undefined ? pltCookieConfig.secure : process.env.NODE_ENV === 'production',
          sameSite: (pltCookieConfig.sameSite || 'lax') as 'lax' | 'strict' | 'none' | boolean
        })

        return res.redirect(`${envConfig.FRONTEND_URL}/auth/google/confirm-link`)
      } else if ('user' in googleAuthResultFromService && googleAuthResultFromService.isLoginViaGoogle) {
        const googleAuthResult = googleAuthResultFromService
        const { user, device, requiresTwoFactorAuth, requiresUntrustedDeviceVerification } = googleAuthResult

        const sltCookieConfig = envConfig.cookie.sltToken

        if (requiresTwoFactorAuth && user.twoFactorMethod) {
          this.logger.log(
            `[GoogleCallback] User ${user.id} requires 2FA (${user.twoFactorMethod}). Initiating SLT flow.`
          )
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
          return res.redirect(`${envConfig.FRONTEND_URL}/buyer/verify-2fa?type=TOTP&${queryParams.toString()}`)
        }

        if (requiresUntrustedDeviceVerification) {
          this.logger.log(
            `[GoogleCallback] User ${user.id} requires untrusted device verification. Initiating SLT flow.`
          )
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
          return res.redirect(`${envConfig.FRONTEND_URL}/buyer/verify-2fa?type=OTP&${queryParams.toString()}`)
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

        const successRedirectUrl = `${envConfig.FRONTEND_URL}`
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
          const result: UserProfileResDTO = {
            id: loginResult.userId,
            email: loginResult.email,
            role: loginResult.role,
            isDeviceTrustedInSession: loginResult.isDeviceTrustedInSession,
            userProfile: loginResult.userProfile
          }
          return result
        }
      }
      this.logger.error(
        '[AuthController googleCallback] Unexpected googleAuthResultFromService structure after checks.',
        googleAuthResultFromService
      )
      throw new ApiException(
        HttpStatus.INTERNAL_SERVER_ERROR,
        'UNEXPECTED_AUTH_RESULT',
        'Error.Auth.Google.UnexpectedResult'
      )
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
  confirmTwoFactorSetup(
    @Body() body: TwoFactorConfirmSetupBodyDTO,
    @ActiveUser('userId') userId: number,
    @Res({ passthrough: true }) res: Response,
    @Ip() ip: string,
    @UserAgent() userAgent: string
  ) {
    return this.authService.confirmTwoFactorSetup(userId, body.setupToken, body.totpCode, res, ip, userAgent)
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
  @ZodSerializerDto(RevokeSessionsResDTO)
  revokeMultipleSessions(@ActiveUser() activeUser: AccessTokenPayload, @Body() body: RevokeSessionsBodyDTO) {
    return this.sessionManagementService.revokeMultipleSessions(
      activeUser.userId,
      activeUser.sessionId,
      activeUser.deviceId,
      body
    )
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
    return this.sessionManagementService.trustCurrentDevice(activeUser.userId, activeUser.deviceId)
  }

  @Post('reverify-password')
  @HttpCode(HttpStatus.OK)
  @UseGuards(AccessTokenGuard)
  @AllowWithoutPasswordReverification()
  @ZodSerializerDto(MessageResDTO)
  async reverifyPassword(
    @ActiveUser() activeUser: AccessTokenPayload,
    @Body() body: ReverifyPasswordBodyType,
    @Ip() ip: string,
    @UserAgent() userAgent: string
  ) {
    this.logger.log(`User ${activeUser.userId} attempting to reverify password for session ${activeUser.sessionId}.`)
    return this.authenticationService.reverifyPassword(activeUser.userId, activeUser.sessionId, body, ip, userAgent)
  }

  @Post('session/send-reverification-otp')
  @HttpCode(HttpStatus.OK)
  @UseGuards(AccessTokenGuard)
  @AllowWithoutPasswordReverification()
  @ZodSerializerDto(MessageResDTO)
  async sendReverificationOtp(@ActiveUser() activeUser: AccessTokenPayload): Promise<{ message: string }> {
    const user = await this.sharedUserRepository.findUnique({ id: activeUser.userId })

    if (!user || !user.email) {
      this.logger.error(`[sendReverificationOtp] User or email not found for ID: ${activeUser.userId}`)
      throw new ApiException(HttpStatus.NOT_FOUND, 'USER_NOT_FOUND', 'Error.User.NotFound')
    }

    await this.authenticationService.initiateSessionReverificationOtp(activeUser.userId, user.email)
    return {
      message: await this.i18nService.translate('Auth.Session.SendReverificationOtpSuccess')
    }
  }

  @Post('google/link-account')
  @Auth([AuthType.Bearer])
  @UsePipes(new ZodValidationPipe(LinkGoogleAccountReqSchema))
  @ZodSerializerDto(UserProfileResSchema)
  async linkGoogleAccount(
    @Req() req: Request,
    @Body() body: LinkGoogleAccountReqDto,
    @Res({ passthrough: true }) res: Response
  ): Promise<any> {
    const loggedInUser = req.user as AccessTokenPayload

    try {
      this.logger.log(`[LinkGoogleAccount] User ${loggedInUser.userId} attempting to link Google ID: ${body.googleId}`)
      const updatedUser = await this.googleService.linkGoogleAccount(
        loggedInUser.userId,
        body.googleId,
        body.googleEmail || 'N/A',
        body.googleName,
        body.googleAvatar
      )

      this.logger.log(
        `[LinkGoogleAccount] Successfully linked Google ID ${body.googleId} to user ${loggedInUser.userId}.`
      )

      return updatedUser
    } catch (error) {
      this.logger.error(
        `[LinkGoogleAccount] Error linking Google ID ${body.googleId} for user ${loggedInUser.userId}:`,
        error
      )
      if (error instanceof ApiException) {
        throw error
      }
      throw new ApiException(
        HttpStatus.INTERNAL_SERVER_ERROR,
        'GOOGLE_LINK_FAILED',
        'Error.Auth.Google.LinkAccountFailed'
      )
    }
  }

  @Get('google/pending-link-details')
  @IsPublic()
  @ZodSerializerDto(PendingLinkDetailsResSchema)
  async getPendingLinkDetails(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response
  ): Promise<PendingLinkDetailsResDto> {
    const pltCookieValue = req.cookies?.[CookieNames.OAUTH_PENDING_LINK_TOKEN]
    const pltCookieConfigFromEnv = (envConfig.cookie as Record<string, any>)?.oauthPendingLinkToken

    const clearCookieName = pltCookieConfigFromEnv?.name || CookieNames.OAUTH_PENDING_LINK_TOKEN
    const clearCookiePath = pltCookieConfigFromEnv?.path || '/'
    const clearCookieDomain = pltCookieConfigFromEnv?.domain

    if (!pltCookieValue) {
      this.logger.warn('[getPendingLinkDetails] OAUTH_PENDING_LINK_TOKEN cookie not found.')
      throw new ApiException(HttpStatus.UNAUTHORIZED, 'PLT_COOKIE_MISSING', 'Error.Auth.Google.Link.NoPendingState')
    }

    try {
      const pltPayload = await this.tokenService.verifyPendingLinkToken(pltCookieValue)

      const existingUser = await this.sharedUserRepository.findUnique({ id: pltPayload.existingUserId })
      if (!existingUser) {
        this.logger.error(
          `[getPendingLinkDetails] Existing user ID ${pltPayload.existingUserId} from PLT not found in DB.`
        )
        if (pltCookieConfigFromEnv) {
          res.clearCookie(clearCookieName, { path: clearCookiePath, domain: clearCookieDomain })
        }
        throw new ApiException(HttpStatus.NOT_FOUND, 'LINK_USER_NOT_FOUND', 'Error.User.NotFound')
      }

      return {
        existingUserEmail: existingUser.email,
        googleEmail: pltPayload.googleEmail,
        googleName: pltPayload.googleName,
        googleAvatar: pltPayload.googleAvatar,
        message: await this.i18nService.translate('Auth.Google.ConfirmLinkDetailsMessage', {
          args: { email: existingUser.email }
        })
      }
    } catch (error) {
      this.logger.warn('[getPendingLinkDetails] Error verifying PLT or fetching user details:', error.message)
      if (pltCookieConfigFromEnv) {
        res.clearCookie(clearCookieName, { path: clearCookiePath, domain: clearCookieDomain })
      }
      if (error instanceof ApiException) throw error
      throw new ApiException(HttpStatus.UNAUTHORIZED, 'PLT_INVALID', 'Error.Auth.Google.Link.InvalidPendingState')
    }
  }

  @Post('google/complete-link-and-login')
  @IsPublic()
  @HttpCode(HttpStatus.OK)
  @ZodSerializerDto(UserProfileResSchema)
  async completeLinkAndLogin(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
    @UserAgent() userAgent: string,
    @Ip() ip: string
  ): Promise<UserProfileResDTO> {
    const pltCookieValue = req.cookies?.[CookieNames.OAUTH_PENDING_LINK_TOKEN]
    const pltCookieConfigFromEnv = (envConfig.cookie as Record<string, any>)?.oauthPendingLinkToken
    const clearCookieName = pltCookieConfigFromEnv?.name || CookieNames.OAUTH_PENDING_LINK_TOKEN
    const clearCookiePath = pltCookieConfigFromEnv?.path || '/'
    const clearCookieDomain = pltCookieConfigFromEnv?.domain

    if (!pltCookieValue) {
      this.logger.warn('[completeLinkAndLogin] OAUTH_PENDING_LINK_TOKEN cookie not found.')
      throw new ApiException(HttpStatus.UNAUTHORIZED, 'PLT_COOKIE_MISSING', 'Error.Auth.Google.Link.NoPendingState')
    }
    res.clearCookie(clearCookieName, { path: clearCookiePath, domain: clearCookieDomain })

    try {
      const pltPayload = await this.tokenService.verifyPendingLinkToken(pltCookieValue)
      this.logger.log(
        `[completeLinkAndLogin] Attempting to link Google ID ${pltPayload.googleId} to existing user ${pltPayload.existingUserId}.`
      )

      const linkedUser = await this.googleService.linkGoogleAccount(
        pltPayload.existingUserId,
        pltPayload.googleId,
        pltPayload.googleEmail,
        pltPayload.googleName,
        pltPayload.googleAvatar
      )

      this.logger.log(`[completeLinkAndLogin] Google account linked. Proceeding to login user ${linkedUser.id}.`)

      const device = await this.deviceService.findOrCreateDevice({
        userId: linkedUser.id,
        userAgent,
        ip
      })

      const loginResult = await this.authenticationService.finalizeOauthLogin(
        linkedUser,
        device,
        false, // rememberMe: false (default)
        ip,
        userAgent,
        'google-link-completion',
        res
      )

      const result: UserProfileResDTO = {
        id: loginResult.userId,
        email: loginResult.email,
        role: loginResult.role,
        isDeviceTrustedInSession: loginResult.isDeviceTrustedInSession,
        userProfile: loginResult.userProfile
      }
      return result
    } catch (error) {
      this.logger.error('[completeLinkAndLogin] Error completing Google link and login:', error.message, error.stack)
      if (error instanceof ApiException) throw error
      throw new ApiException(
        HttpStatus.INTERNAL_SERVER_ERROR,
        'GOOGLE_LINK_COMPLETE_FAILED',
        'Error.Auth.Google.Link.CompleteFailed'
      )
    }
  }

  @Post('google/cancel-pending-link')
  @IsPublic()
  @HttpCode(HttpStatus.OK)
  @ZodSerializerDto(MessageResDTO)
  async cancelPendingLink(@Req() req: Request, @Res({ passthrough: true }) res: Response): Promise<MessageResDTO> {
    const pltCookieValue = req.cookies?.[CookieNames.OAUTH_PENDING_LINK_TOKEN]
    const pltCookieConfigFromEnv = (envConfig.cookie as Record<string, any>)?.oauthPendingLinkToken
    const clearCookieName = pltCookieConfigFromEnv?.name || CookieNames.OAUTH_PENDING_LINK_TOKEN
    const clearCookiePath = pltCookieConfigFromEnv?.path || '/'
    const clearCookieDomain = pltCookieConfigFromEnv?.domain

    if (pltCookieValue && (!pltCookieConfigFromEnv || !pltCookieConfigFromEnv.name)) {
      this.logger.error(
        '[cancelPendingLink] OAUTH_PENDING_LINK_TOKEN cookie configuration is critically missing or incomplete in envConfig, but a PLT cookie was found.'
      )
    }

    if (pltCookieValue && pltCookieConfigFromEnv && pltCookieConfigFromEnv.name) {
      try {
        const pltPayload = await this.tokenService.verifyPendingLinkToken(pltCookieValue)
        this.logger.log(
          `[cancelPendingLink] Cancelling pending link for existing user ${pltPayload.existingUserId} with Google ID ${pltPayload.googleId}.`
        )
      } catch (error) {
        this.logger.warn(
          '[cancelPendingLink] PLT cookie was present but invalid during cancellation. Clearing anyway.',
          error.message
        )
      }
      res.clearCookie(clearCookieName, { path: clearCookiePath, domain: clearCookieDomain })
      this.logger.log('[cancelPendingLink] OAUTH_PENDING_LINK_TOKEN cookie cleared.')
      return {
        message: await this.i18nService.translate('Auth.Google.Link.CancelledSuccessfully')
      }
    } else {
      this.logger.log('[cancelPendingLink] No OAUTH_PENDING_LINK_TOKEN cookie found to cancel.')
      return {
        message: await this.i18nService.translate('Auth.Google.Link.NoPendingStateToCancel')
      }
    }
  }
}
