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
    try {
      const existingUser = await this.coreService.findUserByEmail(body.email)
      if (existingUser) {
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

      return { message: this.i18nService.t('auth.Auth.Otp.SentSuccessfully') }
    } catch (error) {
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
    try {
      const sltCookieValue = req.cookies?.[CookieNames.SLT_TOKEN]
      if (!sltCookieValue) {
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
        throw AuthError.EmailMissingInSltContext()
      }

      if (sltContext.finalized !== '1') {
        throw AuthError.InvalidOTP()
      }

      await this.coreService.completeRegistration({
        ...body,
        email,
        ip,
        userAgent
      })

      this.cookieService.clearSltCookie(res)

      return { message: this.i18nService.t('auth.Auth.Register.Success') }
    } catch (error) {
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

    if (result.requiresDeviceVerification) {
      return {
        statusCode: HttpStatus.OK,
        message: result.message,
        data: {
          requiresDeviceVerification: true,
          verificationType: result.verificationType,
          verificationRedirectUrl: result.verificationRedirectUrl,
          email: result.email
        }
      }
    } else if (result.requires2FA) {
      return {
        statusCode: HttpStatus.OK,
        message: result.message,
        data: {
          requires2FA: true,
          twoFactorMethod: result.twoFactorMethod,
          verificationRedirectUrl: result.verificationRedirectUrl,
          email: result.email
        }
      }
    }

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
      message: result.message,
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

    return {
      message: this.i18nService.t('auth.Auth.Token.Refreshed'),
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
    return {
      message: this.i18nService.t('auth.Auth.Logout.Success')
    }
  }
}
