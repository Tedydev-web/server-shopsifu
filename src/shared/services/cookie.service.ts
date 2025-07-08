import { Injectable } from '@nestjs/common'
import { Response } from 'express'
import { Request } from 'express'
import { COOKIE_DEFINITIONS, CookieDefinitionKey, CookieNames } from 'src/shared/constants/cookie.constant'
import envConfig from 'src/shared/config'
import { TokenService } from './token.service'
import { AccessTokenPayloadCreate, RefreshTokenPayloadCreate } from 'src/shared/types/jwt.type'

@Injectable()
export class CookieService {
  constructor(private readonly tokenService: TokenService) {}

  /**
   * Set access token cookie
   */
  setAccessTokenCookie(res: Response, accessToken: string): void {
    const { name, options } = COOKIE_DEFINITIONS.accessToken
    res.cookie(name, accessToken, options)
  }

  /**
   * Set refresh token cookie
   */
  setRefreshTokenCookie(res: Response, refreshToken: string): void {
    const { name, options } = COOKIE_DEFINITIONS.refreshToken
    res.cookie(name, refreshToken, options)
  }

  /**
   * Set both access and refresh token cookies
   */
  setAuthCookies(res: Response, accessToken: string, refreshToken: string): void {
    // Clear old cookies first to avoid conflicts
    this.clearAuthCookies(res)

    this.setAccessTokenCookie(res, accessToken)
    this.setRefreshTokenCookie(res, refreshToken)
  }

  /**
   * Get access token from cookies
   */
  getAccessTokenFromCookie(req: Request): string | null {
    return req.signedCookies[COOKIE_DEFINITIONS.accessToken.name] || null
  }

  /**
   * Get refresh token from cookies
   */
  getRefreshTokenFromCookie(req: Request): string | null {
    return req.signedCookies[COOKIE_DEFINITIONS.refreshToken.name] || null
  }

  /**
   * Clear all authentication cookies
   */
  clearAuthCookies(res: Response): void {
    res.clearCookie(COOKIE_DEFINITIONS.accessToken.name, COOKIE_DEFINITIONS.accessToken.options)
    res.clearCookie(COOKIE_DEFINITIONS.refreshToken.name, COOKIE_DEFINITIONS.refreshToken.options)
  }

  /**
   * Clear specific cookie
   */
  clearCookie(res: Response, cookieKey: CookieDefinitionKey): void {
    const { name, options } = COOKIE_DEFINITIONS[cookieKey]
    res.clearCookie(name, options)
  }

  /**
   * Set CSRF token cookie
   */
  setCSRFTokenCookie(res: Response, token: string): void {
    const { name, options } = COOKIE_DEFINITIONS.csrfToken
    res.cookie(name, token, options)
  }

  /**
   * Get CSRF token from cookies
   */
  getCSRFTokenFromCookie(req: Request): string | null {
    return req.cookies[COOKIE_DEFINITIONS.csrfToken.name] || null
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
