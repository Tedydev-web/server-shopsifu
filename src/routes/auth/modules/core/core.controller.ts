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
  UseGuards,
  HttpException
} from '@nestjs/common'
import { Request, Response } from 'express'
import { ZodSerializerDto } from 'nestjs-zod'
import { I18nService, I18nContext } from 'nestjs-i18n'

import { CoreService } from './core.service'
import { TypeOfVerificationCode } from 'src/routes/auth/constants/auth.constants'
import {
  CompleteRegistrationDto,
  InitiateRegistrationDto,
  LoginDto,
  LogoutDto,
  MessageResponseDto,
  RefreshTokenDto,
  RefreshTokenResponseDto,
  RegistrationResponseDto
} from './dto/auth.dto'
import { OtpService } from '../otp/otp.service'
import { CookieService } from 'src/routes/auth/shared/cookie/cookie.service'
import { TokenService } from 'src/routes/auth/shared/token/token.service'
import { UserAgent } from 'src/shared/decorators/user-agent.decorator'
import { AccessTokenGuard } from 'src/routes/auth/guards/access-token.guard'
import { AuthError } from 'src/routes/auth/auth.error'
import { CookieNames } from 'src/shared/constants/auth.constant'
import { ActiveUser } from 'src/routes/auth/decorators/active-user.decorator'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'
import { IsPublic } from 'src/routes/auth/decorators/auth.decorator'

@Controller('auth')
export class CoreController {
  private readonly logger = new Logger(CoreController.name)

  constructor(
    private readonly coreService: CoreService,
    private readonly otpService: OtpService,
    private readonly cookieService: CookieService,
    private readonly tokenService: TokenService,
    private readonly i18nService: I18nService
  ) {}

  /**
   * Khởi tạo quá trình đăng ký
   * 1. Nhận email từ người dùng
   * 2. Gửi OTP qua email
   * 3. Tạo SLT token và trả về trong cookie
   */
  @IsPublic()
  @Post('initiate-registration')
  @HttpCode(HttpStatus.OK)
  @ZodSerializerDto(MessageResponseDto)
  async initiateRegistration(
    @Body() body: InitiateRegistrationDto,
    @Ip() ip: string,
    @UserAgent() userAgent: string,
    @Res({ passthrough: true }) res: Response
  ): Promise<MessageResponseDto> {
    this.logger.debug(`[initiateRegistration] Start registration process for email: ${body.email}, IP: ${ip}`)

    try {
      // Kiểm tra xem email đã tồn tại chưa
      const existingUser = await this.coreService.findUserByEmail(body.email)
      if (existingUser) {
        this.logger.warn(`[initiateRegistration] Email ${body.email} already exists`)
        throw AuthError.EmailAlreadyExists()
      }

      // Khởi tạo OTP với SLT cookie
      this.logger.debug(`[initiateRegistration] Initiating OTP with SLT cookie`)
      const sltJwt = await this.otpService.initiateOtpWithSltCookie({
        email: body.email,
        userId: 0, // 0 cho user chưa tồn tại
        deviceId: 0, // 0 cho device chưa tồn tại
        ipAddress: ip,
        userAgent,
        purpose: TypeOfVerificationCode.REGISTER
      })

      this.logger.debug(`[initiateRegistration] SLT JWT generated successfully, length: ${sltJwt.length}`)

      // Set SLT cookie
      this.logger.debug(`[initiateRegistration] Setting SLT cookie in response`)
      this.cookieService.setSltCookie(res, sltJwt, TypeOfVerificationCode.REGISTER)

      // Kiểm tra xem cookies đã được đặt trong response chưa
      this.logger.debug(
        `[initiateRegistration] Response cookies: ${JSON.stringify(res.getHeaders()['set-cookie'] || 'No cookies set')}`
      )

      // Lấy thông báo đã dịch
      const translatedMessage = await this.i18nService.translate('Auth.Otp.SentSuccessfully', {
        lang: I18nContext.current()?.lang || 'vi'
      })

      this.logger.debug(`[initiateRegistration] Registration initiated successfully for ${body.email}`)

      return { message: translatedMessage }
    } catch (error) {
      this.logger.error(`[initiateRegistration] Error during registration initiation: ${error.message}`, error.stack)
      throw error
    }
  }

  /**
   * Hoàn tất đăng ký
   * 1. Kiểm tra SLT token để đảm bảo OTP đã được xác minh
   * 2. Tạo user với thông tin từ người dùng
   */
  @IsPublic()
  @Post('complete-registration')
  @HttpCode(HttpStatus.OK)
  @ZodSerializerDto(RegistrationResponseDto)
  async completeRegistration(
    @Body() body: CompleteRegistrationDto,
    @Ip() ip: string,
    @UserAgent() userAgent: string,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response
  ): Promise<RegistrationResponseDto> {
    this.logger.debug(`[completeRegistration] Processing registration completion, IP: ${ip}`)

    try {
      // Lấy SLT token từ cookie
      const sltCookieValue = req.cookies?.[CookieNames.SLT_TOKEN]
      if (!sltCookieValue) {
        this.logger.warn(`[completeRegistration] SLT cookie missing`)
        throw AuthError.SLTCookieMissing()
      }

      // Xác minh SLT và lấy context
      const sltContext = await this.otpService.validateSltFromCookieAndGetContext(
        sltCookieValue,
        ip,
        userAgent,
        TypeOfVerificationCode.REGISTER
      )

      // Email đảm bảo được lấy từ SLT token context
      const email = sltContext.email
      if (!email) {
        this.logger.error(`[completeRegistration] Email missing in SLT context`)
        throw new HttpException(
          'Email không tìm thấy trong context, vui lòng thực hiện lại từ đầu',
          HttpStatus.BAD_REQUEST
        )
      }

      this.logger.debug(`[completeRegistration] Using email from SLT context: ${email}`)

      // Kiểm tra SLT đã được xác minh chưa
      if (sltContext.finalized !== '1') {
        this.logger.warn(`[completeRegistration] SLT not finalized for email: ${email}`)
        throw AuthError.InvalidOTP()
      }

      // Hoàn tất đăng ký với email từ SLT context
      await this.coreService.completeRegistration({
        ...body,
        email, // Email lấy từ SLT context thay vì từ body
        ip,
        userAgent
      })

      // Xóa SLT cookie
      this.cookieService.clearSltCookie(res)

      // Lấy thông báo đã dịch
      const translatedMessage = await this.i18nService.translate('Auth.Register.Success', {
        lang: I18nContext.current()?.lang || 'vi'
      })

      this.logger.debug(`[completeRegistration] Registration completed successfully for ${email}`)

      return {
        message: translatedMessage
      }
    } catch (error) {
      this.logger.error(`[completeRegistration] Error during registration completion: ${error.message}`, error.stack)
      throw error
    }
  }

  /**
   * Đăng nhập
   */
  @IsPublic()
  @Post('login')
  @HttpCode(HttpStatus.OK)
  async login(
    @Body() body: LoginDto,
    @Ip() ip: string,
    @UserAgent() userAgent: string,
    @Res({ passthrough: true }) res: Response
  ) {
    const result = await this.coreService.login(
      {
        ...body,
        ip,
        userAgent
      },
      res
    )

    // Đảm bảo message đã được dịch (nếu có)
    const message = result.message

    // Kiểm tra nếu kết quả có message dạng i18n key
    if (result.requiresTwoFactorAuth !== undefined || result.requiresDeviceVerification !== undefined) {
      return {
        statusCode: 200,
        message,
        // Thêm dữ liệu phù hợp theo trạng thái
        ...(result.requiresTwoFactorAuth ? { requiresTwoFactorAuth: true } : {}),
        ...(result.requiresDeviceVerification ? { requiresDeviceVerification: true } : {})
      }
    }

    // Trả về kết quả đăng nhập thành công với message tương ứng
    return {
      statusCode: 200,
      message: await this.i18nService.translate('Auth.Login.Success', {
        lang: I18nContext.current()?.lang || 'vi'
      }),
      data: result
    }
  }

  /**
   * Làm mới token
   */
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
    // Lấy refresh token từ cookie
    const refreshToken = this.tokenService.extractRefreshTokenFromRequest(req)
    if (!refreshToken) {
      throw AuthError.MissingRefreshToken()
    }

    // Làm mới token
    const result = await this.coreService.refreshToken(refreshToken, { userAgent, ip }, res)

    return {
      message: await this.i18nService.translate('Auth.Token.Refreshed')
    }
  }

  /**
   * Đăng xuất
   */
  @Post('logout')
  @UseGuards(AccessTokenGuard)
  @HttpCode(HttpStatus.OK)
  @ZodSerializerDto(MessageResponseDto)
  async logout(
    @ActiveUser() activeUser: AccessTokenPayload,
    @Body() _: LogoutDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response
  ): Promise<MessageResponseDto> {
    // Đăng xuất
    await this.coreService.logout(activeUser.userId, activeUser.sessionId, req, res)

    return {
      message: await this.i18nService.translate('Auth.Logout.Success')
    }
  }
}
