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

@Injectable()
export class TokenService {
  constructor(private readonly jwtService: JwtService) {}

  signAccessToken(payload: AccessTokenPayloadCreate): string {
    return this.jwtService.sign(
      { ...payload, uuid: uuidv4() },
      {
        secret: process.env.AUTH_ACCESS_TOKEN_SECRET,
        expiresIn: process.env.AUTH_ACCESS_TOKEN_EXP,
        algorithm: 'HS256'
      }
    )
  }

  signRefreshToken(payload: RefreshTokenPayloadCreate): string {
    return this.jwtService.sign(
      { ...payload, uuid: uuidv4() },
      {
        secret: process.env.AUTH_REFRESH_TOKEN_SECRET,
        expiresIn: process.env.AUTH_REFRESH_TOKEN_EXP,
        algorithm: 'HS256'
      }
    )
  }

  verifyAccessToken(token: string): Promise<AccessTokenPayload> {
    return this.jwtService.verifyAsync(token, {
      secret: process.env.AUTH_ACCESS_TOKEN_SECRET
    })
  }

  verifyRefreshToken(token: string): Promise<RefreshTokenPayload> {
    return this.jwtService.verifyAsync(token, {
      secret: process.env.AUTH_REFRESH_TOKEN_SECRET
    })
  }

  /**
   * Decode token without verification (for debugging purposes)
   */
  decodeToken(token: string): any {
    return this.jwtService.decode(token)
  }

  /**
   * Get token expiration time
   */
  getTokenExpiration(token: string): Date | null {
    try {
      const decoded = this.jwtService.decode(token)
      return decoded?.exp ? new Date(decoded.exp * 1000) : null
    } catch {
      return null
    }
  }

  /**
   * Check if token is expired
   */
  isTokenExpired(token: string): boolean {
    const expiration = this.getTokenExpiration(token)
    return expiration ? expiration < new Date() : true
  }
}
