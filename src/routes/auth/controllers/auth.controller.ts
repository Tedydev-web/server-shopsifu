import { Body, Controller, Get, HttpCode, HttpStatus, Post, Query, Res, UseGuards, Req } from '@nestjs/common'
import { Response, Request } from 'express'
import { ZodSerializerDto, createZodDto } from 'nestjs-zod'
import {
  DisableTwoFactorBodyDTO,
  ForgotPasswordBodyDTO,
  LoginBodyDTO,
  RegisterBodyDTO,
  SendOTPBodyDTO,
  TwoFactorSetupResDTO
} from '../dtos/auth.dto'
import { CoreAuthService } from '../services/core.service'
import { GoogleService } from '../services/social/google.service'
import { ActiveUser } from 'src/shared/decorators/active-user.decorator'
import { IsPublic } from 'src/shared/decorators/auth.decorator'
import { AccessTokenGuard } from 'src/shared/guards/access-token.guard'
import { CookieNames } from 'src/shared/constants/cookie.constant'
import { OtpService } from '../services/otp.service'
import { PasswordService } from '../services/password.service'
import { SessionService } from '../services/session.service'
import { z } from 'zod'
import envConfig from 'src/shared/config'

// Định nghĩa DTO trả về message cho auth
export class AuthMessageResponseDTO extends createZodDto(z.object({ message: z.string() })) {}

const TwoFactorSetupResponseDTO = createZodDto(
  z.object({
    qrCode: z.string(),
    secret: z.string()
  })
)

@Controller('auth')
export class AuthController {
  constructor(
    private readonly coreAuthService: CoreAuthService,
    private readonly googleService: GoogleService,
    private readonly otpService: OtpService,
    private readonly passwordService: PasswordService,
    private readonly sessionService: SessionService
  ) {}

  @IsPublic()
  @Get('csrf')
  @HttpCode(HttpStatus.OK)
  getCsrfToken() {
    return { message: 'auth.success.CSRF_TOKEN_SUCCESS' }
  }

  @Post('register')
  @IsPublic()
  @ZodSerializerDto(AuthMessageResponseDTO)
  register(@Body() body: RegisterBodyDTO, @Req() req: Request) {
    return this.coreAuthService.register(body, req)
  }

  @Post('send-otp')
  @IsPublic()
  @ZodSerializerDto(AuthMessageResponseDTO)
  sendOTP(@Body() body: SendOTPBodyDTO, @Req() req: Request, @Res({ passthrough: true }) res: Response) {
    return this.otpService.sendOTP(body, req, res)
  }

  @Post('login')
  @IsPublic()
  @ZodSerializerDto(AuthMessageResponseDTO)
  login(@Body() body: LoginBodyDTO, @Req() req: Request, @Res({ passthrough: true }) res: Response) {
    return this.coreAuthService.login(body, req, res)
  }

  @Post('refresh-token')
  @HttpCode(HttpStatus.OK)
  refreshToken(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    const refreshToken = req.cookies[CookieNames.REFRESH_TOKEN]
    return this.sessionService.refreshToken({ refreshToken, res })
  }

  @Post('logout')
  @HttpCode(HttpStatus.OK)
  logout(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    const accessToken = this.extractTokenFromHeader(req)
    const refreshToken = req.cookies[CookieNames.REFRESH_TOKEN]
    return this.sessionService.logout({ accessToken, refreshToken, res })
  }

  @Get('google/url')
  getAuthorizationUrl(@Res({ passthrough: true }) res: Response) {
    return this.googleService.getAuthorizationUrl(res)
  }

  @Get('google/callback')
  async googleCallback(
    @Query('code') code: string,
    @Query('state') state: string,
    @Req() req: Request,
    @Res() res: Response
  ) {
    if (!code || !state) {
      // Redirect to a failure page or handle the error appropriately
      const failureRedirectUrl = new URL('/auth/login-failure', envConfig.CLIENT_URL)
      failureRedirectUrl.searchParams.set('error', 'invalid_callback_params')
      return res.redirect(failureRedirectUrl.toString())
    }
    await this.googleService.googleCallback({ code, state }, req, res)
  }

  @Post('forgot-password')
  @HttpCode(HttpStatus.OK)
  @IsPublic()
  @ZodSerializerDto(AuthMessageResponseDTO)
  forgotPassword(@Body() body: ForgotPasswordBodyDTO) {
    return this.passwordService.forgotPassword(body)
  }

  @Post('setup-2fa')
  @UseGuards(AccessTokenGuard)
  @ZodSerializerDto(TwoFactorSetupResponseDTO)
  setupTwoFactorAuth(@ActiveUser('userId') userId: number) {
    return this.coreAuthService.setupTwoFactorAuth(userId)
  }

  @Post('disable-2fa')
  @UseGuards(AccessTokenGuard)
  @ZodSerializerDto(AuthMessageResponseDTO)
  disableTwoFactorAuth(@Body() body: DisableTwoFactorBodyDTO, @ActiveUser('userId') userId: number) {
    return this.coreAuthService.disableTwoFactorAuth({ ...body, userId })
  }

  private extractTokenFromHeader(request: Request): string | undefined {
    const [type, token] = request.headers.authorization?.split(' ') ?? []
    return type === 'Bearer' ? token : undefined
  }
}
