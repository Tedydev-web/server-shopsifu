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

  extractTokenFromRequest(req: Request): string | null {
    return req.cookies?.[envConfig.cookie.accessToken.name] || this.extractTokenFromHeader(req)
  }

  extractRefreshTokenFromRequest(req: Request): string | null {
    return req.cookies?.[envConfig.cookie.refreshToken.name] || req.body?.refreshToken
  }

  setTokenCookies(res: Response, accessToken: string, refreshToken: string, maxAgeForRefreshTokenCookie?: number) {
    const accessTokenConfig = envConfig.cookie.accessToken
    const refreshTokenConfig = envConfig.cookie.refreshToken

    const actualRefreshTokenMaxAge = maxAgeForRefreshTokenCookie ?? refreshTokenConfig.maxAge

    if (accessToken && accessTokenConfig.maxAge > 0) {
      res.cookie(accessTokenConfig.name, accessToken, {
        path: accessTokenConfig.path,
        domain: accessTokenConfig.domain,
        maxAge: accessTokenConfig.maxAge,
        httpOnly: accessTokenConfig.httpOnly,
        secure: accessTokenConfig.secure,
        sameSite: accessTokenConfig.sameSite
      })
    } else {
      console.warn(
        '[DEBUG TokenService] res.cookie SKIPPED for access_token. Reason:',
        !accessToken ? 'AccessToken missing' : 'MaxAge not positive'
      )
    }

    if (refreshToken && actualRefreshTokenMaxAge > 0) {
      res.cookie(refreshTokenConfig.name, refreshToken, {
        path: refreshTokenConfig.path,
        domain: refreshTokenConfig.domain,
        maxAge: actualRefreshTokenMaxAge,
        httpOnly: refreshTokenConfig.httpOnly,
        secure: refreshTokenConfig.secure,
        sameSite: refreshTokenConfig.sameSite
      })
    } else {
      console.warn(
        '[DEBUG TokenService] res.cookie SKIPPED for refresh_token. Reason:',
        !refreshToken ? 'RefreshToken missing' : 'MaxAge not positive'
      )
    }
  }

  clearTokenCookies(res: Response) {
    const accessTokenConfig = envConfig.cookie.accessToken
    const refreshTokenConfig = envConfig.cookie.refreshToken
    const csrfTokenConfig = envConfig.cookie.csrfToken

    res.clearCookie(accessTokenConfig.name, {
      domain: accessTokenConfig.domain,
      path: accessTokenConfig.path,
      httpOnly: accessTokenConfig.httpOnly,
      secure: accessTokenConfig.secure,
      sameSite: accessTokenConfig.sameSite
    })

    res.clearCookie(refreshTokenConfig.name, {
      domain: refreshTokenConfig.domain,
      path: refreshTokenConfig.path,
      httpOnly: refreshTokenConfig.httpOnly,
      secure: refreshTokenConfig.secure,
      sameSite: refreshTokenConfig.sameSite
    })

    // Also clear CSRF token for client
    res.clearCookie(csrfTokenConfig.name, {
      domain: csrfTokenConfig.domain,
      path: csrfTokenConfig.path,
      httpOnly: csrfTokenConfig.httpOnly,
      secure: csrfTokenConfig.secure,
      sameSite: csrfTokenConfig.sameSite
    })
  }

  private extractTokenFromHeader(req: Request): string | null {
    const [type, token] = req.headers.authorization?.split(' ') || []
    return type === 'Bearer' ? token : null
  }
}
