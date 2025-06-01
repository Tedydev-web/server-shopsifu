import { Injectable, CanActivate, ExecutionContext, UnauthorizedException } from '@nestjs/common'
import { Reflector } from '@nestjs/core'
import { REQUEST_USER_KEY, AuthType } from 'src/shared/constants/auth.constant'
import { TokenService } from 'src/routes/auth/providers/token.service'
import { Request } from 'express'
import envConfig from 'src/shared/config'
import {
  AbsoluteSessionLifetimeExceededException,
  InvalidDeviceException,
  InvalidAccessTokenException,
  SessionNotFoundException,
  MismatchedSessionTokenException,
  RemoteSessionRevokedException
} from 'src/routes/auth/auth.error'
import { Prisma } from '@prisma/client'
import { RedisService } from 'src/shared/providers/redis/redis.service'
import { REDIS_KEY_PREFIX } from 'src/shared/constants/redis.constants'
import { AUTH_TYPE_KEY, AuthTypeDecoratorPayload } from 'src/routes/auth/decorators/auth.decorator'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'
import { MissingAccessTokenException } from 'src/routes/auth/auth.error'

@Injectable()
export class AccessTokenGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly tokenService: TokenService,
    private readonly redisService: RedisService
  ) {}
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const authTypePayload = this.reflector.getAllAndOverride<AuthTypeDecoratorPayload | undefined>(AUTH_TYPE_KEY, [
      context.getHandler(),
      context.getClass()
    ])

    if (authTypePayload?.authTypes?.includes(AuthType.None)) {
      return true
    }

    const request = context.switchToHttp().getRequest<Request>()
    const token = this.tokenService.extractTokenFromRequest(request)

    if (!token) {
      throw new MissingAccessTokenException()
    }

    let decodedAccessToken: AccessTokenPayload | undefined = undefined

    try {
      decodedAccessToken = await this.tokenService.verifyAccessToken(token)

      request[REQUEST_USER_KEY] = decodedAccessToken

      const { userId, deviceId, sessionId, jti: accessTokenJti } = decodedAccessToken

      if (!sessionId || !accessTokenJti) {
        throw new InvalidAccessTokenException()
      }

      const isBlacklisted = await this.tokenService.isAccessTokenJtiBlacklisted(accessTokenJti)
      if (isBlacklisted) {
        throw new InvalidAccessTokenException()
      }

      const sessionKey = `${REDIS_KEY_PREFIX.SESSION_DETAILS}${sessionId}`
      const sessionDetails = await this.redisService.hgetall(sessionKey)

      if (!sessionDetails || Object.keys(sessionDetails).length === 0) {
        throw new RemoteSessionRevokedException()
      }

      if (parseInt(sessionDetails.userId, 10) !== userId || parseInt(sessionDetails.deviceId, 10) !== deviceId) {
        throw new MismatchedSessionTokenException()
      }

      if (sessionDetails.currentAccessTokenJti !== accessTokenJti) {
        throw new InvalidAccessTokenException()
      }

      if (sessionDetails.createdAt) {
        const sessionCreatedAt = new Date(sessionDetails.createdAt)
        const sessionAgeMs = new Date().getTime() - sessionCreatedAt.getTime()

        if (sessionAgeMs > envConfig.ABSOLUTE_SESSION_LIFETIME_MS) {
          await this.tokenService.invalidateSession(sessionId, 'ABSOLUTE_LIFETIME_EXCEEDED')
          throw new AbsoluteSessionLifetimeExceededException()
        }
      } else {
        throw new RemoteSessionRevokedException()
      }

      await this.redisService.hset(sessionKey, 'lastActiveAt', new Date().toISOString())

      return true
    } catch (error) {
      const userIdFromToken = decodedAccessToken?.userId

      const details: Prisma.JsonObject = {
        reason: 'ACCESS_TOKEN_VERIFICATION_FAILED',
        originalError: error?.constructor?.name,
        errorMessageInCatch: error instanceof Error ? error.message : 'Unknown error'
      }
      if (decodedAccessToken?.jti) {
        details.accessTokenJti = decodedAccessToken.jti
      }
      if (decodedAccessToken?.sessionId) {
        details.sessionId = decodedAccessToken.sessionId
      }

      if (
        error instanceof AbsoluteSessionLifetimeExceededException ||
        error instanceof SessionNotFoundException ||
        error instanceof RemoteSessionRevokedException ||
        error instanceof InvalidAccessTokenException ||
        error instanceof MismatchedSessionTokenException ||
        error instanceof InvalidDeviceException
      ) {
        throw error
      }

      throw new UnauthorizedException('Error.Auth.Token.InvalidOrExpiredAccessToken')
    }
  }
}
