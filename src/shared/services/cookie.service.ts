import { Injectable } from '@nestjs/common'
import { Response, Request } from 'express'
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
   * Get access token from cookies
   */
  getAccessTokenFromCookie(req: Request): string | null {
    return req.cookies[this.configService.getOrThrow('cookie.accessToken.name')] || null
  }

  /**
   * Get refresh token from cookies
   */
  getRefreshTokenFromCookie(req: Request): string | null {
    return req.cookies[this.configService.getOrThrow('cookie.refreshToken.name')] || null
  }

  /**
   * Clear all authentication cookies
   */
  clearAuthCookies(res: Response): void {
    res.clearCookie(this.configService.getOrThrow('cookie.accessToken.name'))
    res.clearCookie(this.configService.getOrThrow('cookie.refreshToken.name'))
  }
}
