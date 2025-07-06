import { Injectable } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { JwtService } from '@nestjs/jwt'
import {
  AccessTokenPayload,
  AccessTokenPayloadCreate,
  RefreshTokenPayload,
  RefreshTokenPayloadCreate
} from 'src/shared/types/jwt.type'
import { v4 as uuidv4 } from 'uuid'
import { EnvConfigType } from 'src/shared/config'
import { SessionService } from './session.service'

@Injectable()
export class TokenService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService<EnvConfigType>,
    private readonly sessionService: SessionService
  ) {}

  signAccessToken(payload: AccessTokenPayloadCreate) {
    const jwtConfig = this.configService.get('jwt')
    return this.jwtService.sign(
      { ...payload, jti: uuidv4() },
      {
        secret: jwtConfig.accessToken.secret,
        expiresIn: jwtConfig.accessToken.expiresIn,
        algorithm: 'HS256'
      }
    )
  }

  signRefreshToken(payload: RefreshTokenPayloadCreate) {
    const jwtConfig = this.configService.get('jwt')
    return this.jwtService.sign(
      { ...payload, jti: uuidv4() },
      {
        secret: jwtConfig.refreshToken.secret,
        expiresIn: jwtConfig.refreshToken.expiresIn,
        algorithm: 'HS256'
      }
    )
  }

  verifyAccessToken(token: string): Promise<AccessTokenPayload> {
    const jwtConfig = this.configService.get('jwt')
    return this.jwtService.verifyAsync(token, {
      secret: jwtConfig.accessToken.secret
    })
  }

  verifyRefreshToken(token: string): Promise<RefreshTokenPayload> {
    const jwtConfig = this.configService.get('jwt')
    return this.jwtService.verifyAsync(token, {
      secret: jwtConfig.refreshToken.secret
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
