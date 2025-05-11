import { Body, Controller, Get, HttpCode, HttpStatus, Ip, Post, Query, Req, Res, UseGuards } from '@nestjs/common'
import { Response } from 'express'
import { ZodSerializerDto } from 'nestjs-zod'
import {
  GetAuthorizationUrlResDTO,
  LoginBodyDTO,
  LoginResDTO,
  LogoutBodyDTO,
  RefreshTokenBodyDTO,
  RefreshTokenResDTO,
  RegisterBodyDTO,
  RegisterResDTO,
  ResetPasswordBodyDTO,
  SendOTPBodyDTO,
  VerifyCodeBodyDTO,
  VerifyCodeResponseDTO
} from 'src/routes/auth/auth.dto'

import { AuthService } from 'src/routes/auth/auth.service'
import { GoogleService } from 'src/routes/auth/google.service'
import envConfig from 'src/shared/config'
import { IsPublic } from 'src/shared/decorators/auth.decorator'
import { RateLimit } from 'src/shared/decorators/rate-limit.decorator'
import { UserAgent } from 'src/shared/decorators/user-agent.decorator'
import { MessageResDTO } from 'src/shared/dtos/response.dto'
import { RateLimitGuard } from 'src/shared/guards/rate-limit.guard'

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly googleService: GoogleService
  ) {}

  @Post('register')
  @IsPublic()
  @UseGuards(RateLimitGuard)
  @RateLimit({ ttl: 3600, limit: 5 }) // Giới hạn 5 lần đăng ký/giờ
  @ZodSerializerDto(RegisterResDTO)
  register(@Body() body: RegisterBodyDTO) {
    return this.authService.register(body)
  }

  @Post('otp')
  @IsPublic()
  @UseGuards(RateLimitGuard)
  @RateLimit({ ttl: 300, limit: 3 }) // Giới hạn 3 lần gửi OTP/5 phút
  @ZodSerializerDto(MessageResDTO)
  sendOTP(@Body() body: SendOTPBodyDTO) {
    return this.authService.sendOTP(body)
  }

  @Post('login')
  @IsPublic()
  @UseGuards(RateLimitGuard)
  @RateLimit({ ttl: 600, limit: 5 }) // Giới hạn 5 lần đăng nhập/10 phút
  @ZodSerializerDto(LoginResDTO)
  login(@Body() body: LoginBodyDTO, @UserAgent() userAgent: string, @Ip() ip: string) {
    return this.authService.login({
      ...body,
      userAgent,
      ip
    })
  }

  @Post('refresh-token')
  @IsPublic()
  @HttpCode(HttpStatus.OK)
  @ZodSerializerDto(RefreshTokenResDTO)
  refreshToken(@Body() body: RefreshTokenBodyDTO, @UserAgent() userAgent: string, @Ip() ip: string) {
    return this.authService.refreshToken({
      refreshToken: body.refreshToken,
      userAgent,
      ip
    })
  }

  @Post('logout')
  @ZodSerializerDto(MessageResDTO)
  logout(@Body() body: LogoutBodyDTO) {
    return this.authService.logout(body.refreshToken)
  }

  @Get('google-link')
  @IsPublic()
  @ZodSerializerDto(GetAuthorizationUrlResDTO)
  getAuthorizationUrl(@UserAgent() userAgent: string, @Ip() ip: string) {
    return this.googleService.getAuthorizationUrl({
      userAgent,
      ip
    })
  }

  @Get('google/callback')
  @IsPublic()
  async googleCallback(@Query('code') code: string, @Query('state') state: string, @Res() res: Response) {
    try {
      const data = await this.googleService.googleCallback({
        code,
        state
      })
      return res.redirect(
        `${envConfig.GOOGLE_CLIENT_REDIRECT_URI}?accessToken=${data.accessToken}&refreshToken=${data.refreshToken}`
      )
    } catch (error) {
      const message =
        error instanceof Error
          ? error.message
          : 'Đã xảy ra lỗi khi đăng nhập bằng Google, vui lòng thử lại bằng cách khác'
      return res.redirect(`${envConfig.GOOGLE_CLIENT_REDIRECT_URI}?errorMessage=${message}`)
    }
  }

  @Post('verify-code')
  @IsPublic()
  @UseGuards(RateLimitGuard)
  @RateLimit({ ttl: 300, limit: 5 }) // Giới hạn 5 lần xác thực/5 phút
  @ZodSerializerDto(VerifyCodeResponseDTO)
  verifyCode(@Body() body: VerifyCodeBodyDTO, @UserAgent() userAgent: string, @Ip() ip: string) {
    return this.authService.verifyCode({
      ...body,
      userAgent,
      ip
    })
  }

  @Post('reset-password')
  @IsPublic()
  @UseGuards(RateLimitGuard)
  @RateLimit({ ttl: 3600, limit: 3 }) // Giới hạn 3 lần đặt lại mật khẩu/giờ
  @ZodSerializerDto(MessageResDTO)
  resetPassword(@Body() body: ResetPasswordBodyDTO) {
    return this.authService.resetPassword(body)
  }
}
