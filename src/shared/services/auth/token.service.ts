import { Injectable } from '@nestjs/common'
import { JwtService } from '@nestjs/jwt'
import {
  AccessTokenPayload,
  AccessTokenPayloadCreate,
  RefreshTokenPayload,
  RefreshTokenPayloadCreate
} from 'src/shared/types/jwt.type'
import { v4 as uuidv4 } from 'uuid'
import envConfig from 'src/shared/config'
import { SessionService } from './session.service'

@Injectable()
export class TokenService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly sessionService: SessionService
  ) {}

  signAccessToken(payload: AccessTokenPayloadCreate) {
    return this.jwtService.sign(
      { ...payload, jti: uuidv4() },
      {
        secret: envConfig.ACCESS_TOKEN_SECRET,
        expiresIn: envConfig.ACCESS_TOKEN_EXPIRES_IN,
        algorithm: 'HS256'
      }
    )
  }

  signRefreshToken(payload: RefreshTokenPayloadCreate) {
    return this.jwtService.sign(
      { ...payload, jti: uuidv4() },
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

  /**
   * Invalidates a token by adding its JTI to the blacklist.
   * @param token The token to invalidate.
   */
  async invalidateToken(token: string): Promise<void> {
    try {
      // We don't care if it's an access or refresh token, we just need the payload.
      // verifyAsync will throw an error if the token is invalid or expired, which is fine.
      const payload = await this.jwtService.verifyAsync<AccessTokenPayload | RefreshTokenPayload>(token)
      const remainingTime = payload.exp - Math.floor(Date.now() / 1000)

      if (remainingTime > 0) {
        await this.sessionService.addToBlacklist(payload.jti, remainingTime)
      }
    } catch (error) {
      // Ignore errors (e.g., if token is already expired).
      // The goal is just to blacklist it if it's still valid.
    }
  }
}
