import { Injectable, CanActivate, ExecutionContext, Logger, Inject } from '@nestjs/common'
import { Reflector } from '@nestjs/core'
import { Request } from 'express'
import { RedisService } from 'src/shared/providers/redis/redis.service'
import { TokenService } from '../shared/token/token.service'
import { REDIS_SERVICE, TOKEN_SERVICE } from 'src/shared/constants/injection.tokens'
import { AuthError } from '../auth.error'

@Injectable()
export class AccessTokenGuard implements CanActivate {
  private readonly logger = new Logger(AccessTokenGuard.name)

  constructor(
    private readonly reflector: Reflector,
    @Inject(TOKEN_SERVICE) private readonly tokenService: TokenService,
    @Inject(REDIS_SERVICE) private readonly redisService: RedisService
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const isPublic = this.reflector.getAllAndOverride<boolean>('is_public', [context.getHandler(), context.getClass()])

    if (isPublic) {
      return true
    }

    const request = context.switchToHttp().getRequest<Request>()
    const token = this.tokenService.extractTokenFromRequest(request)

    if (!token) {
      this.logger.debug('Access token missing')
      throw AuthError.MissingAccessToken()
    }

    try {
      const payload = await this.tokenService.verifyAccessToken(token)

      // Kiểm tra session có bị vô hiệu hóa không
      if (!payload.sessionId) {
        throw AuthError.MissingSessionIdInToken()
      }

      const isSessionInvalidated = await this.tokenService.isSessionInvalidated(payload.sessionId)
      if (isSessionInvalidated) {
        this.logger.debug(`Session ${payload.sessionId} has been invalidated. Access denied.`)
        throw AuthError.SessionNotFound()
      }

      request.user = payload
      return true
    } catch (error) {
      if (error.message === 'jwt expired') {
        throw AuthError.InvalidAccessToken()
      }

      throw error
    }
  }
}
