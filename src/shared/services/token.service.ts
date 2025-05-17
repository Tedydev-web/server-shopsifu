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

  setTokenCookies(res: Response, accessToken: string, refreshToken: string) {
    const isProduction = envConfig.NODE_ENV === 'production'

    // Access token cookie
    const accessTokenOptions: CookieOptions = {
      httpOnly: true,
      secure: isProduction,
      sameSite: 'strict',
      maxAge: envConfig.ACCESS_TOKEN_COOKIE_MAX_AGE,
      path: '/',
      domain: envConfig.COOKIE_DOMAIN
    }

    // Refresh token cookie (chỉ gửi đến /auth/refresh-token)
    const refreshTokenOptions: CookieOptions = {
      httpOnly: true,
      secure: isProduction,
      sameSite: 'lax',
      maxAge: envConfig.REFRESH_TOKEN_COOKIE_MAX_AGE,
      path: '/auth/refresh-token',
      domain: envConfig.COOKIE_DOMAIN
    }

    res.cookie(CookieNames.ACCESS_TOKEN, accessToken, accessTokenOptions)
    res.cookie(CookieNames.REFRESH_TOKEN, refreshToken, refreshTokenOptions)
  }

  clearTokenCookies(res: Response) {
    res.clearCookie(CookieNames.ACCESS_TOKEN, {
      path: '/',
      domain: envConfig.COOKIE_DOMAIN
    })

    res.clearCookie(CookieNames.REFRESH_TOKEN, {
      path: '/auth/refresh-token',
      domain: envConfig.COOKIE_DOMAIN
    })
  }

  // Phương thức hỗ trợ
  private extractTokenFromHeader(req: Request): string | null {
    const [type, token] = req.headers.authorization?.split(' ') || []
    return type === 'Bearer' ? token : null
  }
}
