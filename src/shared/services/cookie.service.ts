import { Injectable } from '@nestjs/common'
import { Response } from 'express'
import { Request } from 'express'
import { COOKIE_DEFINITIONS } from 'src/shared/constants/cookie.constant'

@Injectable()
export class CookieService {
  /**
   * Set both access and refresh token cookies
   */
  setAuthCookies(res: Response, accessToken: string, refreshToken: string): void {
    // Clear old cookies first to avoid conflicts
    this.clearAuthCookies(res)

    // Set access token cookie
    const { name: accessTokenName, options: accessTokenOptions } = COOKIE_DEFINITIONS.accessToken
    res.cookie(accessTokenName, accessToken, accessTokenOptions)

    // Set refresh token cookie
    const { name: refreshTokenName, options: refreshTokenOptions } = COOKIE_DEFINITIONS.refreshToken
    res.cookie(refreshTokenName, refreshToken, refreshTokenOptions)
  }

  /**
   * Get access token from cookies
   */
  getAccessTokenFromCookie(req: Request): string | null {
    return req.cookies[COOKIE_DEFINITIONS.accessToken.name] || null
  }

  /**
   * Get refresh token from cookies
   */
  getRefreshTokenFromCookie(req: Request): string | null {
    return req.cookies[COOKIE_DEFINITIONS.refreshToken.name] || null
  }

  /**
   * Clear all authentication cookies
   */
  clearAuthCookies(res: Response): void {
    res.clearCookie(COOKIE_DEFINITIONS.accessToken.name)
    res.clearCookie(COOKIE_DEFINITIONS.refreshToken.name)
  }
}
