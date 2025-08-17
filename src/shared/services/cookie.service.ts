import { Injectable } from '@nestjs/common'
import { Response } from 'express'
import { ConfigService } from '@nestjs/config'

@Injectable()
export class CookieService {
  constructor(private readonly configService: ConfigService) {}

  /**
   * Set both access and refresh token cookies
   */
  setAuthCookies(res: Response, accessToken: string, refreshToken: string): void {
    this.clearAuthCookies(res)

    // Lấy options động từ config
    const accessTokenOptions = this.configService.getOrThrow('cookie.accessToken.options')
    const refreshTokenOptions = this.configService.getOrThrow('cookie.refreshToken.options')

    res.cookie(this.configService.getOrThrow('cookie.accessToken.name'), accessToken, accessTokenOptions)
    res.cookie(this.configService.getOrThrow('cookie.refreshToken.name'), refreshToken, refreshTokenOptions)
  }

  /**
   * Clear all authentication cookies
   */
  clearAuthCookies(res: Response): void {
    res.clearCookie(this.configService.getOrThrow('cookie.accessToken.name'))
    res.clearCookie(this.configService.getOrThrow('cookie.refreshToken.name'))
  }
}
