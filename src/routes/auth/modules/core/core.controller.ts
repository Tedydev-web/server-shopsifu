import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Ip,
  Logger,
  Post,
  Req,
  Res,
  HttpException,
  Inject
} from '@nestjs/common'
import { Request, Response } from 'express'
import { ZodSerializerDto } from 'nestjs-zod'
import { I18nService, I18nContext } from 'nestjs-i18n'

import { CoreService } from './core.service'
import { TypeOfVerificationCode } from 'src/shared/constants/auth.constants'
import {
  CompleteRegistrationDto,
  InitiateRegistrationDto,
  LoginDto,
  RefreshTokenDto,
  RefreshTokenResponseDto
} from './auth.dto'
import { MessageResDTO } from 'src/shared/dtos/response.dto'
import { OtpService } from '../otp/otp.service'
import { UserAgent } from 'src/shared/decorators/user-agent.decorator'
import { AuthError } from 'src/routes/auth/auth.error'
import { CookieNames } from 'src/shared/constants/auth.constants'
import { ActiveUser } from 'src/shared/decorators/active-user.decorator'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'
import { IsPublic } from 'src/shared/decorators/auth.decorator'
import { ICookieService, ITokenService } from 'src/shared/types/auth.types'
import { COOKIE_SERVICE, TOKEN_SERVICE } from 'src/shared/constants/injection.tokens'
import { I18nTranslations, I18nPath } from 'src/generated/i18n.generated'

@Controller('auth')
export class CoreController {
  private readonly logger = new Logger(CoreController.name)

  constructor(
    private readonly coreService: CoreService,
    private readonly otpService: OtpService,
    @Inject(COOKIE_SERVICE) private readonly cookieService: ICookieService,
    @Inject(TOKEN_SERVICE) private readonly tokenService: ITokenService,
    private readonly i18nService: I18nService<I18nTranslations>
  ) {}

  @IsPublic()
  @Post('initiate-registration')
  @HttpCode(HttpStatus.OK)
  @ZodSerializerDto(MessageResDTO)
  async initiateRegistration(
    @Body() body: InitiateRegistrationDto,
    @Ip() ip: string,
    @UserAgent() userAgent: string,
    @Res({ passthrough: true }) res: Response
  ): Promise<MessageResDTO> {
    this.logger.debug(`[initiateRegistration] Start registration process for email: ${body.email}, IP: ${ip}`)
    try {
      const existingUser = await this.coreService.findUserByEmail(body.email)
      if (existingUser) {
        this.logger.warn(`[initiateRegistration] Email ${body.email} already exists`)
        throw AuthError.EmailAlreadyExists()
      }

      const sltJwt = await this.otpService.initiateOtpWithSltCookie({
        email: body.email,
        userId: 0,
        deviceId: 0,
        ipAddress: ip,
        userAgent,
        purpose: TypeOfVerificationCode.REGISTER
      })

      this.cookieService.setSltCookie(res, sltJwt, TypeOfVerificationCode.REGISTER)

      this.logger.debug(
        `[initiateRegistration] Language from context for Auth.Otp.SentSuccessfully: ${I18nContext.current()?.lang}`
      )
      let translatedMessage = await this.i18nService.translate('Auth.Otp.SentSuccessfully' as I18nPath)
      if (typeof translatedMessage !== 'string') {
        this.logger.warn(
          `[initiateRegistration] Translation for 'Auth.Otp.SentSuccessfully' did not return a string, falling back to key. Received: ${JSON.stringify(translatedMessage)}`
        )
        translatedMessage = 'Auth.Otp.SentSuccessfully'
      }
      this.logger.debug(`[initiateRegistration] Translated Auth.Otp.SentSuccessfully message: ${translatedMessage}`)
      return { message: translatedMessage }
    } catch (error) {
      this.logger.error(`[initiateRegistration] Error: ${error.message}`, error.stack)
      if (error instanceof HttpException) throw error
      throw AuthError.InternalServerError(error.message)
    }
  }

  @IsPublic()
  @Post('complete-registration')
  @HttpCode(HttpStatus.OK)
  @ZodSerializerDto(MessageResDTO)
  async completeRegistration(
    @Body() body: CompleteRegistrationDto,
    @Ip() ip: string,
    @UserAgent() userAgent: string,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response
  ): Promise<MessageResDTO> {
    this.logger.debug(`[completeRegistration] Processing registration completion, IP: ${ip}`)
    try {
      const sltCookieValue = req.cookies?.[CookieNames.SLT_TOKEN]
      if (!sltCookieValue) {
        this.logger.warn(`[completeRegistration] SLT cookie missing`)
        throw AuthError.SLTCookieMissing()
      }

      const sltContext = await this.otpService.validateSltFromCookieAndGetContext(
        sltCookieValue,
        ip,
        userAgent,
        TypeOfVerificationCode.REGISTER
      )

      const email = sltContext.email
      if (!email) {
        this.logger.error(`[completeRegistration] Email missing in SLT context`)
        throw AuthError.EmailMissingInSltContext()
      }

      if (sltContext.finalized !== '1') {
        this.logger.warn(`[completeRegistration] SLT not finalized for email: ${email}`)
        throw AuthError.InvalidOTP()
      }

      await this.coreService.completeRegistration({
        ...body,
        email,
        ip,
        userAgent
      })

      this.cookieService.clearSltCookie(res)

      this.logger.debug(
        `[completeRegistration] Language from context for Auth.Register.Success: ${I18nContext.current()?.lang}`
      )
      let translatedMessage = await this.i18nService.translate('Auth.Register.Success' as I18nPath)
      if (typeof translatedMessage !== 'string') {
        this.logger.warn(
          `[completeRegistration] Translation for 'Auth.Register.Success' did not return a string, falling back to key. Received: ${JSON.stringify(translatedMessage)}`
        )
        translatedMessage = 'Auth.Register.Success'
      }
      this.logger.debug(`[completeRegistration] Translated Auth.Register.Success message: ${translatedMessage}`)
      return { message: translatedMessage }
    } catch (error) {
      this.logger.error(`[completeRegistration] Error: ${error.message}`, error.stack)
      if (error instanceof HttpException) throw error
      throw AuthError.InternalServerError(error.message)
    }
  }

  @IsPublic()
  @Post('login')
  @HttpCode(HttpStatus.OK)
  async login(
    @Body() body: LoginDto,
    @Ip() ip: string,
    @UserAgent() userAgent: string,
    @Res({ passthrough: true }) res: Response
  ) {
    const result = await this.coreService.login({ ...body, ip, userAgent }, res)

    let responseMessage: string

    // Determine the primary message key or direct message from the service result
    const messageKeyFromService =
      result.messageKey ||
      (result.message && (result.message.startsWith('Auth.') || result.message.startsWith('error.'))
        ? result.message
        : undefined)

    if (messageKeyFromService) {
      this.logger.debug(
        `[Login] Translating service message key: ${messageKeyFromService}, lang: ${I18nContext.current()?.lang}`
      )
      try {
        const translatedMsg = await this.i18nService.translate(messageKeyFromService as I18nPath)
        if (typeof translatedMsg === 'string' && translatedMsg.trim() !== '') {
          responseMessage = translatedMsg
        } else {
          this.logger.warn(
            `[Login] Translation for '${messageKeyFromService}' did not return a valid string, falling back to key. Received: ${JSON.stringify(translatedMsg)}`
          )
          responseMessage = messageKeyFromService
        }
      } catch (e) {
        this.logger.warn(
          `[Login] Failed to translate message key '${messageKeyFromService}', falling back to key. Error: ${e.message}`
        )
        responseMessage = messageKeyFromService
      }
      this.logger.debug(`[Login] Resulting message for service key '${messageKeyFromService}': ${responseMessage}`)
    } else if (result.message && typeof result.message === 'string') {
      // If the service returned a direct message (not a key)
      responseMessage = result.message
      this.logger.debug(`[Login] Using direct message from service: ${responseMessage}`)
    } else {
      // Fallback if no message or messageKey, though service should provide one
      this.logger.warn('[Login] No message or messageKey from service, using default success message.')
      responseMessage = await this.i18nService.translate('Auth.Login.Success' as I18nPath)
    }

    if (result.requiresDeviceVerification) {
      return {
        statusCode: HttpStatus.OK,
        message: responseMessage, // Use the determined and possibly translated message
        data: {
          requiresDeviceVerification: true,
          verificationType: result.verificationType,
          verificationRedirectUrl: result.verificationRedirectUrl
        }
      }
    }

    // If login is successful without device verification, use the standard login success message
    // This part of the message logic can be simplified as responseMessage should already be Auth.Login.Success
    // if result from service didn't specify requiresDeviceVerification and had a success message/messageKey.
    // However, to be explicit for this path:
    let loginSuccessMessage = await this.i18nService.translate('Auth.Login.Success' as I18nPath)
    if (typeof loginSuccessMessage !== 'string' || loginSuccessMessage.trim() === '') {
      this.logger.warn(
        `[Login] Translation for 'Auth.Login.Success' did not return a valid string, falling back to key. Received: ${JSON.stringify(loginSuccessMessage)}`
      )
      loginSuccessMessage = 'Auth.Login.Success'
    }
    this.logger.debug(`[Login] Translated Auth.Login.Success message for direct login: ${loginSuccessMessage}`)

    const responseData = {
      user: {
        id: result.user.id,
        email: result.user.email,
        role: result.user.role,
        isDeviceTrustedInSession: result.user.isDeviceTrustedInSession,
        userProfile: result.user.userProfile
          ? {
              username: result.user.userProfile.username,
              avatar: result.user.userProfile.avatar
            }
          : null
      }
    }

    return {
      statusCode: HttpStatus.OK,
      message: loginSuccessMessage, // Use the explicitly translated login success message
      data: responseData
    }
  }

  @IsPublic()
  @Post('refresh-token')
  @HttpCode(HttpStatus.OK)
  @ZodSerializerDto(RefreshTokenResponseDto)
  async refreshToken(
    @Body() _: RefreshTokenDto,
    @UserAgent() userAgent: string,
    @Ip() ip: string,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response
  ): Promise<RefreshTokenResponseDto> {
    const refreshTokenValue = this.tokenService.extractRefreshTokenFromRequest(req)
    if (!refreshTokenValue) {
      throw AuthError.MissingRefreshToken()
    }

    const { accessToken } = await this.coreService.refreshToken(refreshTokenValue, { userAgent, ip }, res)

    this.logger.debug(`[refreshToken] Language from context for Auth.Token.Refreshed: ${I18nContext.current()?.lang}`)
    let translatedMessage = await this.i18nService.translate('Auth.Token.Refreshed' as I18nPath)
    if (typeof translatedMessage !== 'string') {
      this.logger.warn(
        `[refreshToken] Translation for 'Auth.Token.Refreshed' did not return a string, falling back to key. Received: ${JSON.stringify(translatedMessage)}`
      )
      translatedMessage = 'Auth.Token.Refreshed'
    }
    this.logger.debug(`[refreshToken] Translated Auth.Token.Refreshed message: ${translatedMessage}`)

    return {
      message: translatedMessage,
      accessToken
    }
  }

  @Post('logout')
  @HttpCode(HttpStatus.OK)
  @ZodSerializerDto(MessageResDTO)
  async logout(
    @ActiveUser() activeUser: AccessTokenPayload,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response
  ): Promise<MessageResDTO> {
    await this.coreService.logout(activeUser.userId, activeUser.sessionId, req, res)
    this.logger.debug(`[Logout] Language from context for Auth.Logout.Success: ${I18nContext.current()?.lang}`)
    let translatedLogoutSuccessMessage = await this.i18nService.translate('Auth.Logout.Success' as I18nPath)
    if (typeof translatedLogoutSuccessMessage !== 'string') {
      this.logger.warn(
        `[Logout] Translation for 'Auth.Logout.Success' did not return a string, falling back to key. Received: ${JSON.stringify(translatedLogoutSuccessMessage)}`
      )
      translatedLogoutSuccessMessage = 'Auth.Logout.Success'
    }
    this.logger.debug(`[Logout] Translated Auth.Logout.Success message: ${translatedLogoutSuccessMessage}`)

    return {
      message: translatedLogoutSuccessMessage
    }
  }
}
