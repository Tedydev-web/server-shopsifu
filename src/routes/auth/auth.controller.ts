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
  UsePipes,
  HttpException
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
  TwoFactorConfirmSetupBodyDTO,
  TwoFactorConfirmSetupResDTO,
  RememberMeBodyDTO,
  RefreshTokenSuccessResDTO,
  UserProfileResDTO,
  ReverifyPasswordBodyType,
  ChangePasswordBodyDTO,
  MessageResDTO
} from 'src/routes/auth/auth.dto'
import {
  RevokeSessionParamsDTO,
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

import { GoogleService } from './google.service'
import envConfig from 'src/shared/config'
import { ActiveUser } from './decorators/active-user.decorator'
import { IsPublic } from './decorators/auth.decorator'
import { UserAgent } from 'src/shared/decorators/user-agent.decorator'
import { EmptyBodyDTO } from 'src/shared/dtos/request.dto'
import { MessageResSchema } from 'src/shared/models/response.model'
import { TokenService } from 'src/routes/auth/providers/token.service'
import { SkipThrottle, Throttle } from '@nestjs/throttler'
import { CookieNames, AuthType } from 'src/shared/constants/auth.constant'
import { AccessTokenPayload, PendingLinkTokenPayloadCreate } from 'src/shared/types/jwt.type'
import { I18nContext } from 'nestjs-i18n'
import { I18nService } from 'nestjs-i18n'
import { SessionManagementService } from 'src/routes/auth/services/session-management.service'
import { AccessTokenGuard } from './guards/access-token.guard'
import { RolesGuard } from './guards/roles.guard'
import { z } from 'zod'
import { Auth } from './decorators/auth.decorator'
import { OtpService, SltContextData } from './providers/otp.service'
import { TypeOfVerificationCode } from './constants/auth.constants'
import { RedisService } from 'src/shared/providers/redis/redis.service'
import { JwtService } from '@nestjs/jwt'
import { AuthenticationService } from './services/authentication.service'
import { ApiException } from 'src/shared/exceptions/api.exception'
import { Buffer } from 'buffer'
import { RevokeSessionsResDTO } from './dtos/session-management.dto'
import { AllowWithoutPasswordReverification } from './guards/password-reverification.guard'
import { UserRepository } from './repositories/shared-user.repo'
import { LinkGoogleAccountReqDto, LinkGoogleAccountReqSchema } from './dtos/link-google-account.dto'
import { UserProfileResSchema, LoginSessionResSchema, GoogleAuthStateType } from './auth.model'
import { ZodValidationPipe } from 'nestjs-zod'
import { PendingLinkDetailsResSchema, PendingLinkDetailsResDto } from './dtos/pending-link-details.dto'
import { DeviceService } from './providers/device.service'
import ms from 'ms'
import { TwoFactorAuthService } from './services/two-factor-auth.service'
import {
  SltCookieMissingException,
  SltContextMaxAttemptsReachedException,
  MaxVerificationAttemptsExceededException,
  InvalidRefreshTokenException,
  SltContextInvalidPurposeException,
  DeviceMismatchException,
  SltContextFinalizedException
} from './auth.error'
import { Prisma } from '@prisma/client'
import { PasswordAuthService } from './services/password-auth.service'
import { SltHelperService } from './services/slt-helper.service'

interface PltCookieConfigType {
  name: string
  path?: string
  domain?: string
  maxAge: number
  httpOnly?: boolean
  secure?: boolean
  sameSite?: 'lax' | 'strict' | 'none' | boolean
}

@Controller('auth')
export class AuthController {
  private readonly logger = new Logger(AuthController.name)

  constructor(
    private readonly googleService: GoogleService,
    private readonly tokenService: TokenService,
    private readonly i18nService: I18nService,
    private readonly sessionManagementService: SessionManagementService,
    private readonly otpService: OtpService,
    private readonly redisService: RedisService,
    private readonly jwtService: JwtService,
    private readonly authenticationService: AuthenticationService,
    private readonly userRepository: UserRepository,
    private readonly deviceService: DeviceService,
    private readonly twoFactorAuthService: TwoFactorAuthService,
    private readonly passwordAuthService: PasswordAuthService,
    private readonly sltHelperService: SltHelperService
  ) {}

  @Post('register')
  @IsPublic()
  @Throttle({ short: { limit: 5, ttl: 10000 } })
  @ZodSerializerDto(RegisterResDTO)
  async register(
    @Body() body: RegisterBodyDTO,
    @UserAgent() userAgent: string,
    @Ip() ip: string,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response
  ) {
    const sltCookieValue = req.cookies?.[CookieNames.SLT_TOKEN]
    if (!sltCookieValue) {
      throw new SltCookieMissingException()
    }

    await this.authenticationService.register({ ...body, userAgent, ip, sltCookieValue })

    // Clear SLT token after successful registration as flow is complete
    this.tokenService.clearSltCookie(res)

    return {
      message: await this.i18nService.translate('Auth.Register.Success', {
        lang: I18nContext.current()?.lang
      })
    }
  }

  @Post('send-otp')
  @IsPublic()
  @Throttle({ short: { limit: 3, ttl: 60000 } })
  @ZodSerializerDto(MessageResDTO)
  async sendOTP(
    @Body() body: SendOTPBodyDTO,
    @Res({ passthrough: true }) res: Response,
    @Ip() ip: string,
    @UserAgent() userAgent: string
  ) {
    const { email, type } = body
    const userIdForCooldown: number | undefined = undefined

    const user = await this.userRepository.findUnique({ email })

    if (type === TypeOfVerificationCode.REGISTER && user) {
      throw new ApiException(HttpStatus.CONFLICT, 'EmailInUse', 'Error.Auth.Register.EmailInUse')
    }
    if (type === TypeOfVerificationCode.RESET_PASSWORD && !user) {
      throw new ApiException(HttpStatus.NOT_FOUND, 'EmailNotFound', 'Error.Auth.Email.NotFound')
    }

    if (
      type === TypeOfVerificationCode.REGISTER ||
      type === TypeOfVerificationCode.RESET_PASSWORD ||
      type === TypeOfVerificationCode.VERIFY_NEW_EMAIL
    ) {
      const tempDeviceId = 0

      const sltInitiationUserId = user?.id

      if (type === TypeOfVerificationCode.VERIFY_NEW_EMAIL && !sltInitiationUserId) {
        throw new ApiException(HttpStatus.BAD_REQUEST, 'UserContextRequired', 'Error.Auth.User.NotFound')
      }

      const sltJwt = await this.otpService.initiateOtpWithSltCookie({
        email: email,
        userId: sltInitiationUserId || 0,
        deviceId: tempDeviceId,
        ipAddress: ip,
        userAgent: userAgent,
        purpose: type
      })

      this.sltHelperService.setSltCookie(res, sltJwt, type)
    } else {
      await this.otpService.sendOTP(email, type, user?.id)
    }

    const message = await this.i18nService.translate('Auth.Otp.SentSuccessfully', {
      lang: I18nContext.current()?.lang
    })
    return { message }
  }

  @Post('verify-code')
  @IsPublic()
  @Throttle({ short: { limit: 5, ttl: 10000 } })
  @UseZodSchemas(
    { schema: UserProfileResSchema, predicate: hasProperty('id') },
    { schema: LoginSessionResSchema, predicate: hasProperty('message') },
    { schema: MessageResSchema, predicate: hasProperty('message') }
  )
  async verifyCode(
    @Body() body: VerifyCodeBodyDTO,
    @UserAgent() userAgent: string,
    @Ip() ip: string,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response
  ) {
    const sltCookieValue = req.cookies?.[envConfig.cookie.sltToken.name]
    if (!sltCookieValue) {
      throw new SltCookieMissingException()
    }

    try {
      // Kiểm tra và lấy context của SLT mà không xác minh OTP
      const sltContext = await this.otpService.validateSltFromCookieAndGetContext(sltCookieValue, ip, userAgent)

      // Xử lý các loại purpose khác nhau
      switch (sltContext.purpose) {
        case TypeOfVerificationCode.LOGIN_UNTRUSTED_DEVICE_OTP: {
          // Hoàn tất đăng nhập cho untrusted device - phương thức này sẽ tự xác minh OTP
          const result = await this.authenticationService.completeLoginWithUntrustedDeviceOtp(
            { code: body.code, rememberMe: body.rememberMe, userAgent, ip },
            sltContext,
            res
          )
          return result
        }
        case TypeOfVerificationCode.LOGIN_2FA: {
          // Hoàn tất đăng nhập 2FA - phương thức này sẽ tự xác minh OTP
          const result = await this.twoFactorAuthService.verifyTwoFactor(
            { code: body.code, rememberMe: body.rememberMe, userAgent, ip },
            sltContext,
            res
          )
          return result
        }
        // Các trường hợp khác: REGISTER, RESET_PASSWORD, VERIFY_NEW_EMAIL, v.v.
        default: {
          // Với các trường hợp không phải đăng nhập, thực hiện xác minh OTP
          await this.otpService.verifySltOtpStage(sltCookieValue, body.code, ip, userAgent)
          const message = await this.i18nService.translate('Auth.Otp.VerifiedSuccessfully', {
            lang: I18nContext.current()?.lang
          })
          return { message }
        }
      }
    } catch (error) {
      this.logger.error(`[AuthController.verifyCode] Error verifying code: ${error.message}`, error.stack)
      throw error
    }
  }

  @Post('login')
  @IsPublic()
  @HttpCode(HttpStatus.OK)
  @Throttle({ short: { limit: 5, ttl: 10000 } })
  @UseZodSchemas(
    { schema: UserProfileResSchema, predicate: hasProperty('id') },
    { schema: LoginSessionResSchema, predicate: hasProperty('message') }
  )
  async login(
    @Body() body: LoginBodyDTO,
    @UserAgent() userAgent: string,
    @Ip() ip: string,
    @Res({ passthrough: true }) res: Response
  ) {
    return this.authenticationService.login({ ...body, userAgent, ip }, res)
  }

  @Post('refresh-token')
  @IsPublic()
  @HttpCode(HttpStatus.OK)
  @Throttle({ short: { limit: 10, ttl: 10000 } })
  @ZodSerializerDto(RefreshTokenSuccessResDTO)
  async refreshToken(
    @Body() _: RefreshTokenBodyDTO,
    @UserAgent() userAgent: string,
    @Ip() ip: string,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response
  ): Promise<RefreshTokenSuccessResDTO> {
    const refreshTokenFromCookie = this.tokenService.extractRefreshTokenFromRequest(req)

    if (!refreshTokenFromCookie) {
      throw new InvalidRefreshTokenException()
    }

    const result = await this.tokenService.refreshTokenSilently(refreshTokenFromCookie, userAgent, ip)

    if (!result) {
      throw new InvalidRefreshTokenException()
    }

    this.tokenService.setTokenCookies(
      res,
      result.accessToken,
      result.refreshToken || refreshTokenFromCookie,
      result.maxAgeForRefreshTokenCookie
    )

    const message = await this.i18nService.translate('Auth.Token.Refreshed', {
      lang: I18nContext.current()?.lang
    })

    return { message, accessToken: result.accessToken }
  }

  @Post('logout')
  @HttpCode(HttpStatus.OK)
  @UseGuards(AccessTokenGuard)
  @ZodSerializerDto(MessageResDTO)
  logout(@Body() _: LogoutBodyDTO, @Req() req: Request, @Res({ passthrough: true }) res: Response) {
    return this.authenticationService.logout(req, res)
  }

  @Get('google-link')
  @IsPublic()
  @ZodSerializerDto(GetAuthorizationUrlResDTO)
  @SkipThrottle()
  getAuthorizationUrl(
    @UserAgent() userAgent: string,
    @Ip() ip: string,
    @Res({ passthrough: true }) res: Response,
    @Query('flow') flow?: string,
    @ActiveUser() activeUser?: AccessTokenPayload
  ) {
    let stateObjectExtra: Record<string, any> = {}
    if (flow === 'profile_link' && activeUser?.userId) {
      stateObjectExtra = {
        flow: 'profile_link',
        userIdIfLinking: activeUser.userId
      }
    }

    const { url, nonce } = this.googleService.getAuthorizationUrl({
      userAgent,
      ip,
      ...stateObjectExtra
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
        ) as GoogleAuthStateType & { nonce: string }
        nonceFromStateParam = decodedStateObj?.nonce

        userAgent = decodedStateObj?.userAgent || userAgent
        ip = decodedStateObj?.ip || ip
        if (typeof decodedStateObj?.rememberMe === 'boolean') {
          rememberMeFromState = decodedStateObj.rememberMe
        }

        if (decodedStateObj?.flow === 'profile_link' && typeof decodedStateObj?.userIdIfLinking === 'number') {
          const googleTokens = await this.googleService.getGoogleTokens(code)
          if (!googleTokens || !googleTokens.id_token) {
            return res.redirect(
              `${envConfig.FRONTEND_URL}/profile/settings?googleLinkStatus=error&errorCode=TOKEN_FETCH_FAILED`
            )
          }
          const googlePayload = await this.googleService.verifyGoogleIdToken(googleTokens.id_token)

          if (!googlePayload || !googlePayload.sub || !googlePayload.email) {
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
            return res.redirect(
              `${envConfig.FRONTEND_URL}/profile/settings?googleLinkStatus=success&userEmail=${encodeURIComponent(linkedUserProfile.email)}`
            )
          } catch (linkError) {
            let errorCode = 'LINK_FAILED'
            if (linkError instanceof ApiException) {
              errorCode = linkError.errorCode || errorCode
            }
            return res.redirect(
              `${envConfig.FRONTEND_URL}/profile/settings?googleLinkStatus=error&errorCode=${errorCode}&message=${encodeURIComponent(linkError.message)}`
            )
          }
        }
      } catch (e) {
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
        return res.redirect(
          `${envConfig.FRONTEND_URL}/auth/callback/google?error=${googleAuthResultFromService.errorCode}&errorMessage=${encodeURIComponent(googleAuthResultFromService.errorMessage)}`
        )
      } else if ('needsLinking' in googleAuthResultFromService && googleAuthResultFromService.needsLinking) {
        const linkResult = googleAuthResultFromService

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
          throw new ApiException(
            HttpStatus.INTERNAL_SERVER_ERROR,
            'SERVER_CONFIG_ERROR',
            'Error.Server.ConfigError.MissingOAuthCookie'
          )
        }

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

      throw new ApiException(
        HttpStatus.INTERNAL_SERVER_ERROR,
        'UNEXPECTED_AUTH_RESULT',
        'Error.Auth.Google.UnexpectedResult'
      )
    } catch (error) {
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
  @Throttle({ short: { limit: 3, ttl: 60000 } })
  @ZodSerializerDto(MessageResDTO)
  resetPassword(
    @Body() body: ResetPasswordBodyDTO,
    @UserAgent() userAgent: string,
    @Ip() ip: string,
    @Req() req: Request
  ) {
    const sltCookieValue = req.cookies?.[CookieNames.SLT_TOKEN]
    if (!sltCookieValue) {
      throw new ApiException(HttpStatus.BAD_REQUEST, 'SltTokenMissing', 'Error.Auth.Session.InvalidLogin')
    }
    return this.passwordAuthService.resetPassword({ ...body, userAgent, ip, sltCookieValue })
  }

  @Post('password/change')
  @HttpCode(HttpStatus.OK)
  @UseGuards(AccessTokenGuard)
  @Throttle({ short: { limit: 5, ttl: 10000 } })
  @ZodSerializerDto(MessageResDTO)
  changePassword(
    @ActiveUser('userId') userId: number,
    @Body() body: ChangePasswordBodyDTO,
    @Ip() ip: string,
    @UserAgent() userAgent: string
  ) {
    return this.passwordAuthService.changePassword(userId, body.currentPassword, body.newPassword, ip, userAgent)
  }

  @Post('2fa/setup')
  @UseGuards(AccessTokenGuard)
  @HttpCode(HttpStatus.OK)
  @Throttle({ short: { limit: 5, ttl: 10000 } })
  @ZodSerializerDto(TwoFactorSetupResDTO)
  async setupTwoFactorAuth(
    @ActiveUser() activeUser: AccessTokenPayload,
    @Ip() ip: string,
    @UserAgent() userAgent: string,
    @Res({ passthrough: true }) res: Response
  ) {
    if (!activeUser || !activeUser.userId || activeUser.deviceId === undefined) {
      throw new ApiException(HttpStatus.UNAUTHORIZED, 'Unauthorized', 'Error.Auth.Access.Unauthorized')
    }
    const result = await this.twoFactorAuthService.setupTwoFactorAuth(
      activeUser.userId,
      activeUser.deviceId,
      ip,
      userAgent
    )

    if (result.sltJwt) {
      const sltCookieConfig = envConfig.cookie.sltToken
      res.cookie(sltCookieConfig.name, result.sltJwt, {
        httpOnly: true,
        secure: envConfig.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: sltCookieConfig.maxAge,
        path: sltCookieConfig.path || '/'
      })
    } else {
      throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, '2FASetupError', 'Error.Auth.2FA.SetupFailed')
    }

    return {
      secret: result.secret,
      uri: result.uri
    }
  }

  @Post('2fa/confirm-setup')
  @UseGuards(AccessTokenGuard)
  @HttpCode(HttpStatus.OK)
  @Throttle({ short: { limit: 5, ttl: 10000 } })
  @ZodSerializerDto(TwoFactorConfirmSetupResDTO)
  async confirmTwoFactorSetup(
    @ActiveUser() activeUser: AccessTokenPayload,
    @Body() body: TwoFactorConfirmSetupBodyDTO,
    @Ip() ip: string,
    @UserAgent() userAgent: string,
    @Res({ passthrough: true }) res: Response,
    @Req() req: Request
  ) {
    if (!activeUser || !activeUser.userId) {
      throw new ApiException(HttpStatus.UNAUTHORIZED, 'Unauthorized', 'Error.Auth.Access.Unauthorized')
    }

    const sltCookieValue = req.cookies?.[CookieNames.SLT_TOKEN]
    if (!sltCookieValue) {
      throw new ApiException(HttpStatus.BAD_REQUEST, 'SltCookieMissing', 'Error.Auth.2FA.SetupTokenMissing')
    }

    const result = await this.twoFactorAuthService.confirmTwoFactorSetup(
      activeUser.userId,
      sltCookieValue,
      body.totpCode,
      res,
      ip,
      userAgent
    )

    this.tokenService.clearSltCookie(res)

    return result
  }

  @Post('2fa/disable')
  @Throttle({ short: { limit: 3, ttl: 60000 } })
  @ZodSerializerDto(MessageResDTO)
  disableTwoFactorAuth(
    @Body() body: DisableTwoFactorBodyDTO,
    @ActiveUser('userId') userId: number,
    @Ip() ip: string,
    @UserAgent() userAgent: string,
    @Req() req: Request
  ) {
    // Lấy SLT cookie nếu có, nhưng không bắt buộc
    const sltCookieValue = req.cookies?.[CookieNames.SLT_TOKEN]

    return this.twoFactorAuthService.disableTwoFactorAuth({
      ...body,
      userId,
      ip,
      userAgent,
      sltCookieValue
    })
  }

  @Post('2fa/verify')
  @HttpCode(HttpStatus.OK)
  @Throttle({ short: { limit: 5, ttl: 10000 } })
  @ZodSerializerDto(LoginSessionResSchema)
  async verifyTwoFactor(
    @Body() body: TwoFactorVerifyBodyDTO,
    @UserAgent() userAgent: string,
    @Ip() ip: string,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response
  ): Promise<any> {
    const sltCookieValue = req.cookies?.[CookieNames.SLT_TOKEN]
    let sltContext: (SltContextData & { sltJti: string }) | null = null

    try {
      // Kiểm tra SLT - bắt buộc vì đây là luồng đa bước (đăng nhập)
      if (!sltCookieValue) {
        throw new SltCookieMissingException()
      }

      sltContext = await this.otpService.validateSltFromCookieAndGetContext(
        sltCookieValue as string,
        ip,
        userAgent,
        TypeOfVerificationCode.LOGIN_2FA
      )

      const result = await this.twoFactorAuthService.verifyTwoFactor({ ...body, userAgent, ip }, sltContext, res)

      return result
    } catch (error) {
      if (error instanceof ApiException) {
        throw error
      }

      throw error
    }
  }

  @Post('remember-me')
  @HttpCode(HttpStatus.OK)
  @ZodSerializerDto(MessageResDTO)
  setRememberMe(
    @ActiveUser() activeUser: AccessTokenPayload,
    @Body() body: RememberMeBodyDTO,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
    @Ip() ip: string,
    @UserAgent() userAgent: string
  ) {
    return this.authenticationService.setRememberMe(activeUser, body.rememberMe, req, res, ip, userAgent)
  }

  @Get('sessions')
  @UseGuards(AccessTokenGuard, RolesGuard)
  @ZodSerializerDto(GetSessionsGroupedByDeviceResDTO)
  async getActiveSessions(
    @ActiveUser() activeUser: AccessTokenPayload,
    @Query() query: GetSessionsByDeviceQueryDTO
  ): Promise<z.infer<typeof GetSessionsGroupedByDeviceResSchema>> {
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
    @UserAgent() userAgent: string,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response
  ) {
    try {
      const sltCookieValue = req.cookies?.[CookieNames.SLT_TOKEN]
      const result = await this.authenticationService.reverifyPassword(
        activeUser.userId,
        activeUser.sessionId,
        body,
        ip,
        userAgent,
        sltCookieValue,
        res
      )
      return result
    } catch (error) {
      if (error instanceof HttpException) {
        throw error
      }
      throw error
    }
  }

  @Post('session/send-reverification-otp')
  @HttpCode(HttpStatus.OK)
  @UseGuards(AccessTokenGuard)
  @AllowWithoutPasswordReverification()
  @ZodSerializerDto(MessageResDTO)
  async sendReverificationOtp(
    @ActiveUser() activeUser: AccessTokenPayload,
    @Ip() ip: string,
    @UserAgent() userAgent: string,
    @Res({ passthrough: true }) res: Response
  ): Promise<{ message: string }> {
    const sltJwt = await this.authenticationService.initiateSessionReverificationOtp(activeUser, ip, userAgent)

    const sltCookieConfig = envConfig.cookie.sltToken
    if (sltCookieConfig && sltJwt) {
      res.cookie(sltCookieConfig.name, sltJwt, {
        path: sltCookieConfig.path,
        domain: sltCookieConfig.domain,
        maxAge: sltCookieConfig.maxAge,
        httpOnly: sltCookieConfig.httpOnly,
        secure: sltCookieConfig.secure,
        sameSite: sltCookieConfig.sameSite as 'lax' | 'strict' | 'none' | boolean
      })
    } else {
      throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'SltSetupError', 'Error.Auth.Slt.SetupFailed')
    }

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
      const updatedUser = await this.googleService.linkGoogleAccount(
        loggedInUser.userId,
        body.googleId,
        body.googleEmail || 'N/A',
        body.googleName,
        body.googleAvatar
      )

      return updatedUser
    } catch (error) {
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
      throw new ApiException(HttpStatus.UNAUTHORIZED, 'PLT_COOKIE_MISSING', 'Error.Auth.Google.Link.NoPendingState')
    }

    try {
      const pltPayload = await this.tokenService.verifyPendingLinkToken(pltCookieValue)

      const existingUser = await this.userRepository.findUnique({ id: pltPayload.existingUserId })
      if (!existingUser) {
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
      throw new ApiException(HttpStatus.UNAUTHORIZED, 'PLT_COOKIE_MISSING', 'Error.Auth.Google.Link.NoPendingState')
    }
    res.clearCookie(clearCookieName, { path: clearCookiePath, domain: clearCookieDomain })

    try {
      const pltPayload = await this.tokenService.verifyPendingLinkToken(pltCookieValue)

      const linkedUser = await this.googleService.linkGoogleAccount(
        pltPayload.existingUserId,
        pltPayload.googleId,
        pltPayload.googleEmail,
        pltPayload.googleName,
        pltPayload.googleAvatar
      )

      const device = await this.deviceService.findOrCreateDevice({
        userId: linkedUser.id,
        userAgent,
        ip
      })

      const loginResult = await this.authenticationService.finalizeOauthLogin(
        linkedUser,
        device,
        false,
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

    if (pltCookieValue && pltCookieConfigFromEnv && pltCookieConfigFromEnv.name) {
      try {
        const pltPayload = await this.tokenService.verifyPendingLinkToken(pltCookieValue)
      } catch (error) {
        res.clearCookie(clearCookieName, { path: clearCookiePath, domain: clearCookieDomain })
      }
      return {
        message: await this.i18nService.translate('Auth.Google.Link.CancelledSuccessfully')
      }
    } else {
      return {
        message: await this.i18nService.translate('Auth.Google.Link.NoPendingStateToCancel')
      }
    }
  }

  @Post('login/untrusted-device/complete')
  @HttpCode(HttpStatus.OK)
  @Throttle({ short: { limit: 5, ttl: 10000 } })
  @ZodSerializerDto(LoginSessionResSchema)
  async completeLoginUntrustedDevice(
    @Body() body: TwoFactorVerifyBodyDTO,
    @UserAgent() userAgent: string,
    @Ip() ip: string,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response
  ): Promise<any> {
    const sltCookieValue = req.cookies?.[CookieNames.SLT_TOKEN]
    let sltContext: (SltContextData & { sltJti: string }) | null = null

    try {
      if (!sltCookieValue) {
        throw new SltCookieMissingException()
      }

      sltContext = await this.otpService.validateSltFromCookieAndGetContext(
        sltCookieValue,
        ip,
        userAgent,
        TypeOfVerificationCode.LOGIN_UNTRUSTED_DEVICE_OTP
      )

      const result = await this.authenticationService.completeLoginWithUntrustedDeviceOtp(
        { ...body, userAgent, ip },
        sltContext,
        res
      )

      return result
    } catch (error) {
      if (
        error instanceof SltContextFinalizedException ||
        error instanceof SltContextMaxAttemptsReachedException ||
        error instanceof MaxVerificationAttemptsExceededException ||
        error instanceof SltContextInvalidPurposeException ||
        error instanceof DeviceMismatchException ||
        error instanceof SltCookieMissingException ||
        (error instanceof ApiException && error.errorCode === 'Error.Auth.Session.SltContextNotFound') ||
        (error instanceof ApiException && error.errorCode === 'Error.Auth.Session.SltExpired') ||
        (error instanceof ApiException && error.errorCode === 'Error.Auth.Session.SltInvalid')
      ) {
        throw error
      }

      throw error
    }
  }
}
