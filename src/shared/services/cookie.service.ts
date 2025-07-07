import { Injectable } from '@nestjs/common'
import { Response } from 'express'
import { Request } from 'express'
import { COOKIE_DEFINITIONS, CookieNames } from 'src/shared/constants/cookie.constant'
import envConfig from 'src/shared/config'
import { TokenService } from './token.service'
import { AccessTokenPayloadCreate, RefreshTokenPayloadCreate } from 'src/shared/types/jwt.type'

@Injectable()
export class CookieService {
  constructor(private readonly tokenService: TokenService) {}

  /**
   * Set access token cookie
   */
  setAccessTokenCookie(res: Response, payload: AccessTokenPayloadCreate): void {
    const accessToken = this.tokenService.signAccessToken(payload)
    const cookieOptions = COOKIE_DEFINITIONS.accessToken.options

    res.cookie(CookieNames.ACCESS_TOKEN, accessToken, {
      ...cookieOptions,
      maxAge: cookieOptions.maxAge || 15 * 60 * 1000 // 15 minutes default
    })
  }

  /**
   * Set refresh token cookie
   */
  setRefreshTokenCookie(res: Response, payload: RefreshTokenPayloadCreate): void {
    const refreshToken = this.tokenService.signRefreshToken(payload)
    const cookieOptions = COOKIE_DEFINITIONS.refreshToken.options

    res.cookie(CookieNames.REFRESH_TOKEN, refreshToken, {
      ...cookieOptions,
      maxAge: cookieOptions.maxAge || 7 * 24 * 60 * 60 * 1000 // 7 days default
    })
  }

  /**
   * Set both access and refresh token cookies
   */
  setAuthCookies(
    res: Response,
    accessPayload: AccessTokenPayloadCreate,
    refreshPayload: RefreshTokenPayloadCreate
  ): void {
    this.setAccessTokenCookie(res, accessPayload)
    this.setRefreshTokenCookie(res, refreshPayload)
  }

  /**
   * Get access token from cookies
   */
  getAccessTokenFromCookie(req: Request): string | null {
    return req.signedCookies[CookieNames.ACCESS_TOKEN] || null
  }

  /**
   * Get refresh token from cookies
   */
  getRefreshTokenFromCookie(req: Request): string | null {
    return req.signedCookies[CookieNames.REFRESH_TOKEN] || null
  }

  /**
   * Clear all authentication cookies
   */
  clearAuthCookies(res: Response): void {
    const cookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax' as const,
      path: '/',
      signed: true,
      maxAge: 0
    }

    res.cookie(CookieNames.ACCESS_TOKEN, '', cookieOptions)
    res.cookie(CookieNames.REFRESH_TOKEN, '', cookieOptions)
  }

  /**
   * Clear specific cookie
   */
  clearCookie(res: Response, cookieName: string): void {
    const cookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax' as const,
      path: '/',
      signed: true,
      maxAge: 0
    }

    res.cookie(cookieName, '', cookieOptions)
  }

  /**
   * Set CSRF token cookie
   */
  setCSRFTokenCookie(res: Response, token: string): void {
    const cookieOptions = COOKIE_DEFINITIONS.csrfToken.options

    res.cookie(CookieNames.CSRF_TOKEN, token, {
      ...cookieOptions,
      httpOnly: false // CSRF token cần accessible từ JavaScript
    })
  }

  /**
   * Get CSRF token from cookies
   */
  getCSRFTokenFromCookie(req: Request): string | null {
    return req.cookies[CookieNames.CSRF_TOKEN] || null
  }

  /**
   * Validate if cookies are present
   */
  hasAuthCookies(req: Request): boolean {
    return !!(this.getAccessTokenFromCookie(req) || this.getRefreshTokenFromCookie(req))
  }

  /**
   * Get cookie options for specific environment
   */
  getCookieOptions(cookieType: keyof typeof COOKIE_DEFINITIONS) {
    return COOKIE_DEFINITIONS[cookieType].options
  }
}
