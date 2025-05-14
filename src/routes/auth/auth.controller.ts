import { Body, Controller, Get, HttpCode, HttpStatus, Ip, Post, Query, Res } from '@nestjs/common'
import { Response } from 'express'
import { ZodSerializerDto } from 'nestjs-zod'
import {
  ResetPasswordBodyDTO,
  GetAuthorizationUrlResDTO,
  LoginBodyDTO,
  LoginResDTO,
  LogoutBodyDTO,
  RefreshTokenBodyDTO,
  RefreshTokenResDTO,
  RegisterBodyDTO,
  RegisterResDTO,
  SendOTPBodyDTO,
  VerifyOTPBodyDTO,
  VerifyOTPResDTO,
  TwoFactorSetupResDTO
} from 'src/routes/auth/auth.dto'

import { AuthService } from 'src/routes/auth/auth.service'
import { GoogleService } from 'src/routes/auth/google.service'
import envConfig from 'src/shared/config'
import { ActiveUser } from 'src/shared/decorators/active-user.decorator'
import { IsPublic } from 'src/shared/decorators/auth.decorator'
import { RateLimit } from 'src/shared/decorators/rate-limit.decorator'
import { UserAgent } from 'src/shared/decorators/user-agent.decorator'
import { EmptyBodyDTO } from 'src/shared/dtos/request.dto'
import { MessageResDTO } from 'src/shared/dtos/response.dto'
import { ApiResponseDTO } from 'src/shared/dtos/response.dto'

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly googleService: GoogleService
  ) {}

  @Post('register')
  @IsPublic()
  @RateLimit({ limit: 5, ttl: 3600 })
  @ZodSerializerDto(ApiResponseDTO)
  async register(@Body() body: RegisterBodyDTO) {
    const user = await this.authService.register(body)
    return {
      success: true,
      statusCode: HttpStatus.CREATED,
      message: {
        code: 'AUTH.USER_REGISTERED_SUCCESSFULLY'
      },
      data: user
    }
  }

  @Post('otp')
  @IsPublic()
  @RateLimit({ limit: 3, ttl: 300 })
  @ZodSerializerDto(ApiResponseDTO)
  async sendOTP(@Body() body: SendOTPBodyDTO, @UserAgent() userAgent: string, @Ip() ip: string) {
    const result = await this.authService.sendOTP({
      ...body,
      userAgent,
      ip
    })
    return {
      success: true,
      statusCode: HttpStatus.OK,
      message: {
        code: 'AUTH.OTP_SENT_SUCCESSFULLY'
      }
    }
  }

  @Post('login')
  @IsPublic()
  @RateLimit({ limit: 5, ttl: 600 })
  @ZodSerializerDto(ApiResponseDTO)
  async login(@Body() body: LoginBodyDTO, @UserAgent() userAgent: string, @Ip() ip: string) {
    const tokens = await this.authService.login({
      ...body,
      userAgent,
      ip
    })
    return {
      success: true,
      statusCode: HttpStatus.OK,
      message: {
        code: 'AUTH.LOGIN_SUCCESSFUL'
      },
      data: tokens
    }
  }

  @Post('refresh-token')
  @IsPublic()
  @HttpCode(HttpStatus.OK)
  @ZodSerializerDto(ApiResponseDTO)
  async refreshToken(@Body() body: RefreshTokenBodyDTO, @UserAgent() userAgent: string, @Ip() ip: string) {
    const tokens = await this.authService.refreshToken({
      refreshToken: body.refreshToken,
      userAgent,
      ip
    })
    return {
      success: true,
      statusCode: HttpStatus.OK,
      message: {
        code: 'AUTH.TOKEN_REFRESHED_SUCCESSFULLY'
      },
      data: tokens
    }
  }

  @Post('logout')
  @ZodSerializerDto(ApiResponseDTO)
  async logout(@Body() body: LogoutBodyDTO) {
    await this.authService.logout(body.refreshToken)
    return {
      success: true,
      statusCode: HttpStatus.OK,
      message: {
        code: 'AUTH.LOGOUT_SUCCESSFUL'
      }
    }
  }

  @Post('reset-password')
  @IsPublic()
  @RateLimit({ limit: 3, ttl: 300 })
  @ZodSerializerDto(ApiResponseDTO)
  async resetPassword(@Body() body: ResetPasswordBodyDTO) {
    await this.authService.resetPassword(body)
    return {
      success: true,
      statusCode: HttpStatus.OK,
      message: {
        code: 'AUTH.PASSWORD_RESET_SUCCESSFUL'
      }
    }
  }

  @Post('2fa/setup')
  @RateLimit({ limit: 3, ttl: 300 })
  @ZodSerializerDto(ApiResponseDTO)
  async setupTwoFactorAuth(@Body() _: EmptyBodyDTO, @ActiveUser('userId') userId: number) {
    const result = await this.authService.setupTwoFactorAuth(userId)
    return {
      success: true,
      statusCode: HttpStatus.OK,
      message: {
        code: 'AUTH.TOTP_SETUP_SUCCESSFUL'
      },
      data: result
    }
  }

  @Post('verify-code')
  @IsPublic()
  @RateLimit({ limit: 3, ttl: 300 })
  @ZodSerializerDto(ApiResponseDTO)
  async verifyOTP(@Body() body: VerifyOTPBodyDTO, @UserAgent() userAgent: string, @Ip() ip: string) {
    const result = await this.authService.verifyOTP(body, userAgent, ip)
    return {
      success: true,
      statusCode: HttpStatus.OK,
      message: {
        code: 'AUTH.OTP_VERIFIED_SUCCESSFULLY'
      },
      data: result
    }
  }

  @Get('google-link')
  @IsPublic()
  @ZodSerializerDto(ApiResponseDTO)
  getAuthorizationUrl(@UserAgent() userAgent: string, @Ip() ip: string) {
    const url = this.googleService.getAuthorizationUrl({
      userAgent,
      ip
    })
    return {
      success: true,
      statusCode: HttpStatus.OK,
      data: url
    }
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
}
