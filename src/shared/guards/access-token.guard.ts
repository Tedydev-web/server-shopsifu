import { Injectable, CanActivate, ExecutionContext, UnauthorizedException, Inject, HttpException } from '@nestjs/common'
import { Request } from 'express'
import { REQUEST_USER_KEY } from 'src/shared/constants/auth.constant'
import { CookieNames } from 'src/shared/constants/cookie.constant'
import { TokenService } from 'src/shared/services/token.service'
import * as tokens from 'src/shared/constants/injection.tokens'
import { SessionService } from '../services/session.service'
import { AuthError } from 'src/routes/auth/auth.error'

@Injectable()
export class AccessTokenGuard implements CanActivate {
  constructor(
    @Inject(tokens.TOKEN_SERVICE) private readonly tokenService: TokenService,
    @Inject(tokens.SESSION_SERVICE) private readonly sessionService: SessionService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Request>()
    const accessToken = this.extractToken(request)

    if (!accessToken) {
      throw AuthError.AccessTokenRequired
    }

    try {
      // 1. Verify access token
      const payload = await this.tokenService.verifyAccessToken(accessToken)

      // 2. Check if token is blacklisted
      const [isBlacklisted, session] = await Promise.all([
        this.sessionService.isBlacklisted(payload.jti),
        this.sessionService.getSession(payload.sessionId),
      ])

      if (isBlacklisted || !session) {
        throw AuthError.InvalidAccessToken
      }

      // 3. Store user info in request for downstream use
      request[REQUEST_USER_KEY] = {
        userId: payload.userId,
        sessionId: payload.sessionId,
        roleId: payload.roleId,
        roleName: payload.roleName,
        deviceId: session.deviceId,
        jti: payload.jti,
      }

      return true
    } catch (error) {
      // Ensure standardized errors are thrown
      if (error instanceof HttpException) {
        throw error
      }
      throw AuthError.InvalidAccessToken
    }
  }

  private extractToken(request: Request): string | undefined {
    // 1. Priority: Get from cookie
    const fromCookie = request.cookies[CookieNames.ACCESS_TOKEN]
    if (fromCookie) {
      return fromCookie
    }

    // 2. Fallback: Get from header
    const [type, token] = request.headers.authorization?.split(' ') ?? []
    return type === 'Bearer' ? token : undefined
  }
}
