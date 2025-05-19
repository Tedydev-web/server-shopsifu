import { Injectable } from '@nestjs/common'
import { JwtService } from '@nestjs/jwt'
import envConfig from 'src/shared/config'
import {
  AccessTokenPayload,
  AccessTokenPayloadCreate,
  RefreshTokenPayload,
  RefreshTokenPayloadCreate
} from 'src/shared/types/jwt.type'
import { v4 as uuidv4 } from 'uuid'
import { Request, Response, CookieOptions } from 'express'
import { CookieNames } from 'src/shared/constants/auth.constant'

@Injectable()
export class TokenService {
  constructor(private readonly jwtService: JwtService) {}

  signAccessToken(payload: AccessTokenPayloadCreate) {
    return this.jwtService.sign(
      { ...payload, uuid: uuidv4() },
      {
        secret: envConfig.ACCESS_TOKEN_SECRET,
        expiresIn: envConfig.ACCESS_TOKEN_EXPIRES_IN,
        algorithm: 'HS256'
      }
    )
  }

  signRefreshToken(payload: RefreshTokenPayloadCreate) {
    return this.jwtService.sign(
      { ...payload, uuid: uuidv4() },
      {
        secret: envConfig.REFRESH_TOKEN_SECRET,
        expiresIn: envConfig.REFRESH_TOKEN_EXPIRES_IN,
        algorithm: 'HS256'
      }
    )
  }

  verifyAccessToken(token: string): Promise<AccessTokenPayload> {
    return this.jwtService.verifyAsync(token, {
      secret: envConfig.ACCESS_TOKEN_SECRET
    })
  }

  verifyRefreshToken(token: string): Promise<RefreshTokenPayload> {
    return this.jwtService.verifyAsync(token, {
      secret: envConfig.REFRESH_TOKEN_SECRET
    })
  }

  // Các phương thức mới cho cookie-based auth
  extractTokenFromRequest(req: Request): string | null {
    // Thứ tự ưu tiên: Cookie -> Authorization header
    return req.cookies?.[CookieNames.ACCESS_TOKEN] || this.extractTokenFromHeader(req)
  }

  extractRefreshTokenFromRequest(req: Request): string | null {
    // Thứ tự ưu tiên: Cookie -> Body (để tương thích ngược)
    return req.cookies?.[CookieNames.REFRESH_TOKEN] || req.body?.refreshToken
  }

  setTokenCookies(res: Response, accessToken: string, refreshToken: string, maxAgeForRefreshTokenCookie?: number) {
    const isProduction = envConfig.NODE_ENV === 'production'

    const actualRefreshTokenMaxAge = maxAgeForRefreshTokenCookie ?? envConfig.REFRESH_TOKEN_COOKIE_MAX_AGE

    // Access token cookie
    const accessTokenOptions: CookieOptions = {
      httpOnly: true,
      secure: isProduction,
      sameSite: 'lax',
      maxAge: envConfig.ACCESS_TOKEN_COOKIE_MAX_AGE,
      path: '/',
      domain: envConfig.COOKIE_DOMAIN
    }

    // Refresh token cookie
    const refreshTokenOptions: CookieOptions = {
      httpOnly: true,
      secure: isProduction,
      sameSite: 'lax',
      maxAge: actualRefreshTokenMaxAge,
      path: '/api/v1/auth',
      domain: envConfig.COOKIE_DOMAIN
    }

    if (accessToken && envConfig.ACCESS_TOKEN_COOKIE_MAX_AGE > 0) {
      res.cookie(CookieNames.ACCESS_TOKEN, accessToken, accessTokenOptions)
    } else {
      console.warn(
        '[DEBUG TokenService] res.cookie SKIPPED for access_token. Reason:',
        !accessToken ? 'AccessToken missing' : 'MaxAge not positive'
      )
    }

    if (refreshToken && actualRefreshTokenMaxAge > 0) {
      res.cookie(CookieNames.REFRESH_TOKEN, refreshToken, refreshTokenOptions)
    } else {
      console.warn(
        '[DEBUG TokenService] res.cookie SKIPPED for refresh_token. Reason:',
        !refreshToken ? 'RefreshToken missing' : 'MaxAge not positive'
      )
    }
  }

  clearTokenCookies(res: Response) {
    const cookieOptionsBase: CookieOptions = {
      domain: envConfig.COOKIE_DOMAIN,
      httpOnly: true,
      secure: envConfig.NODE_ENV === 'production',
      sameSite: 'lax'
    }

    res.clearCookie(CookieNames.ACCESS_TOKEN, {
      ...cookieOptionsBase,
      path: '/'
    })

    res.clearCookie(CookieNames.REFRESH_TOKEN, {
      ...cookieOptionsBase,
      path: '/api/v1/auth'
    })

    // Also clear CSRF token for client
    res.clearCookie(CookieNames.CSRF_TOKEN, {
      ...cookieOptionsBase,
      httpOnly: false,
      path: '/'
    })
  }

  // Phương thức hỗ trợ
  private extractTokenFromHeader(req: Request): string | null {
    const [type, token] = req.headers.authorization?.split(' ') || []
    return type === 'Bearer' ? token : null
  }
}
