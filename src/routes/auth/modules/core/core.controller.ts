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
  Inject,
  forwardRef
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
import { AccessTokenPayload } from 'src/routes/auth/shared/jwt.type'
import { IsPublic } from 'src/shared/decorators/auth.decorator'
import { ICookieService, ITokenService } from 'src/routes/auth/shared/auth.types'
import { COOKIE_SERVICE, SLT_SERVICE, TOKEN_SERVICE } from 'src/shared/constants/injection.tokens'
import { I18nTranslations, I18nPath } from 'src/generated/i18n.generated'
import { AuthVerificationService } from 'src/routes/auth/services/auth-verification.service'
import { SLTService } from 'src/routes/auth/shared/services/slt.service'

@Controller('auth')
export class CoreController {
  private readonly logger = new Logger(CoreController.name)

  constructor(
    private readonly coreService: CoreService,
    private readonly otpService: OtpService,
    @Inject(forwardRef(() => AuthVerificationService))
    private readonly authVerificationService: AuthVerificationService,
    @Inject(COOKIE_SERVICE) private readonly cookieService: ICookieService,
    @Inject(TOKEN_SERVICE) private readonly tokenService: ITokenService,
    private readonly i18nService: I18nService<I18nTranslations>,
    @Inject(SLT_SERVICE) private readonly sltService: SLTService
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
    this.logger.log(`[initiateRegistration] Khởi tạo đăng ký cho email: ${body.email}`)

    // Kiểm tra email đã tồn tại chưa
    await this.coreService.checkEmailNotExists(body.email)

    // Tạo và lưu một user tạm thời
    const tempUser = await this.coreService.createTemporaryUser(body.email)

    // Tạo device tạm thời
    const tempDevice = await this.coreService.createTemporaryDevice(tempUser.id, userAgent, ip)

    // Sử dụng AuthVerificationService để khởi tạo quá trình xác thực
    const verificationResult = await this.authVerificationService.initiateVerification(
      {
        userId: tempUser.id,
        deviceId: tempDevice.id,
        email: body.email,
        ipAddress: ip,
        userAgent,
        purpose: TypeOfVerificationCode.REGISTER,
        metadata: {
          email: body.email,
          registrationStep: 'initiate'
        }
      },
      res
    )

    return {
      message: verificationResult.message || this.i18nService.t('auth.Auth.Register.EmailSent')
    }
  }

  /**
   * Hoàn thành đăng ký
   */
  @IsPublic()
  @Post('complete-registration')
  async completeRegistration(
    @Body() body: CompleteRegistrationDto,
    @Ip() ip: string,
    @UserAgent() userAgent: string,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response
  ): Promise<MessageResDTO> {
    this.logger.log(`[completeRegistration] Hoàn tất đăng ký cho email: ${body.email}`)

    // Lấy SLT cookie từ request
    const sltCookieValue = req.cookies?.slt_token

    if (!sltCookieValue) {
      throw AuthError.SLTCookieMissing()
    }

    try {
      // Xác thực SLT và lấy context
      const sltContext = await this.sltService.validateSltFromCookieAndGetContext(
        sltCookieValue,
        ip,
        userAgent,
        TypeOfVerificationCode.REGISTER
      )

      // Tạo mật khẩu cho user
      if (body.password !== body.confirmPassword) {
        throw AuthError.InvalidPassword()
      }

      // Hoàn tất đăng ký user
      await this.coreService.completeRegistration({
        email: body.email,
        password: body.password,
        confirmPassword: body.confirmPassword,
        firstName: body.firstName,
        lastName: body.lastName,
        username: body.username,
        phoneNumber: body.phoneNumber,
        ip,
        userAgent
      })

      // Đánh dấu SLT đã được xử lý
      await this.sltService.finalizeSlt(sltContext.sltJti)

      // Xóa SLT cookie
      this.cookieService.clearSltCookie(res)

      return { message: this.i18nService.t('auth.Auth.Register.Success') }
    } catch (error) {
      this.logger.error(`[completeRegistration] Error: ${error.message}`, error.stack)

      // Xóa SLT cookie trong trường hợp lỗi
      this.cookieService.clearSltCookie(res)

      if (error instanceof AuthError) {
        throw error
      }

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

  /**
   * Làm mới token
   */
  @IsPublic()
  @Post('refresh-token')
  async refreshToken(
    @Body() _: RefreshTokenDto,
    @UserAgent() userAgent: string,
    @Ip() ip: string,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response
  ): Promise<RefreshTokenResponseDto> {
    try {
      const refreshToken = this.tokenService.extractRefreshTokenFromRequest(req)

      if (!refreshToken) {
        throw AuthError.MissingRefreshToken()
      }

      const deviceInfo = {
        ipAddress: ip,
        userAgent
      }

      const { accessToken } = await this.coreService.refreshToken(refreshToken, deviceInfo, res)

      return { accessToken }
    } catch (error) {
      if (error instanceof AuthError) throw error
      throw AuthError.InternalServerError(error.message)
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
