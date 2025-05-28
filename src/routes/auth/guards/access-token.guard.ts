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
import { AuditLogService, AuditLogStatus } from 'src/routes/audit-log/audit-log.service'
import { ApiException } from 'src/shared/exceptions/api.exception'
import { Prisma } from '@prisma/client'
import { RedisService } from 'src/shared/providers/redis/redis.service'
import { REDIS_KEY_PREFIX } from 'src/shared/constants/redis.constants'
import { AUTH_TYPE_KEY, AuthTypeDecoratorPayload } from 'src/routes/auth/decorators/auth.decorator'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'

@Injectable()
export class AccessTokenGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly tokenService: TokenService,
    private readonly auditLogService: AuditLogService,
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
      throw MissingAccessTokenException
    }

    let decodedAccessToken: AccessTokenPayload | undefined = undefined

    try {
      decodedAccessToken = await this.tokenService.verifyAccessToken(token)
      this.auditLogService.recordAsync({
        action: 'ACCESS_TOKEN_GUARD_DECODED',
        userId: decodedAccessToken?.userId,
        status: AuditLogStatus.SUCCESS,
        ipAddress: request.ip,
        userAgent: request.headers['user-agent'] as string,
        errorMessage: `Decoded access token successfully. JTI: ${decodedAccessToken?.jti}, SessionID: ${decodedAccessToken?.sessionId}`,
        details: { tokenPayload: JSON.stringify(decodedAccessToken) } as Prisma.JsonObject
      })
      request[REQUEST_USER_KEY] = decodedAccessToken

      const { userId, deviceId, sessionId, jti: accessTokenJti } = decodedAccessToken

      if (!sessionId || !accessTokenJti) {
        this.auditLogService.recordAsync({
          action: 'ACCESS_TOKEN_GUARD_DENY',
          userId,
          status: AuditLogStatus.FAILURE,
          ipAddress: request.ip,
          userAgent: request.headers['user-agent'] as string,
          errorMessage: 'Missing sessionId or JTI in access token payload.',
          details: { reason: 'MISSING_SESSION_ID_OR_JTI_IN_TOKEN' } as Prisma.JsonObject
        })
        throw InvalidAccessTokenException
      }

      const isBlacklisted = await this.tokenService.isAccessTokenJtiBlacklisted(accessTokenJti)
      if (isBlacklisted) {
        this.auditLogService.recordAsync({
          action: 'ACCESS_TOKEN_GUARD_DENY',
          userId,
          status: AuditLogStatus.FAILURE,
          ipAddress: request.ip,
          userAgent: request.headers['user-agent'] as string,
          errorMessage: `Access token JTI ${accessTokenJti} is blacklisted.`,
          details: { reason: 'ACCESS_TOKEN_JTI_BLACKLISTED', accessTokenJti } as Prisma.JsonObject
        })
        throw InvalidAccessTokenException
      }

      const sessionKey = `${REDIS_KEY_PREFIX.SESSION_DETAILS}${sessionId}`
      const sessionDetails = await this.redisService.hgetall(sessionKey)

      if (!sessionDetails || Object.keys(sessionDetails).length === 0) {
        this.auditLogService.recordAsync({
          action: 'ACCESS_TOKEN_GUARD_DENY',
          userId,
          status: AuditLogStatus.FAILURE,
          ipAddress: request.ip,
          userAgent: request.headers['user-agent'] as string,
          errorMessage: `Session ${sessionId} not found in Redis. Assumed revoked remotely.`,
          details: { reason: 'SESSION_NOT_FOUND_IN_REDIS_REVOKED_REMOTELY', sessionId } as Prisma.JsonObject
        })
        throw RemoteSessionRevokedException
      }

      if (parseInt(sessionDetails.userId, 10) !== userId || parseInt(sessionDetails.deviceId, 10) !== deviceId) {
        this.auditLogService.recordAsync({
          action: 'ACCESS_TOKEN_GUARD_DENY',
          userId,
          status: AuditLogStatus.FAILURE,
          ipAddress: request.ip,
          userAgent: request.headers['user-agent'] as string,
          errorMessage: `Mismatched userId/deviceId in session ${sessionId}. Token: (u${userId},d${deviceId}), Session: (u${sessionDetails.userId},d${sessionDetails.deviceId})`,
          details: {
            reason: 'SESSION_USER_DEVICE_MISMATCH',
            sessionId,
            tokenUserId: userId,
            tokenDeviceId: deviceId,
            sessionUserId: sessionDetails.userId,
            sessionDeviceId: sessionDetails.deviceId
          } as Prisma.JsonObject
        })
        throw MismatchedSessionTokenException
      }

      if (sessionDetails.currentAccessTokenJti !== accessTokenJti) {
        this.auditLogService.recordAsync({
          action: 'ACCESS_TOKEN_GUARD_DENY',
          userId,
          status: AuditLogStatus.FAILURE,
          ipAddress: request.ip,
          userAgent: request.headers['user-agent'] as string,
          errorMessage: `Stale access token used for session ${sessionId}. Current JTI in session: ${sessionDetails.currentAccessTokenJti}, Token JTI: ${accessTokenJti}.`,
          details: {
            reason: 'STALE_ACCESS_TOKEN_JTI',
            sessionId,
            tokenJti: accessTokenJti,
            sessionCurrentJti: sessionDetails.currentAccessTokenJti
          } as Prisma.JsonObject
        })
        throw InvalidAccessTokenException
      }

      if (sessionDetails.createdAt) {
        const sessionCreatedAt = new Date(sessionDetails.createdAt)
        const sessionAgeMs = new Date().getTime() - sessionCreatedAt.getTime()

        if (sessionAgeMs > envConfig.ABSOLUTE_SESSION_LIFETIME_MS) {
          this.auditLogService.recordAsync({
            action: 'ACCESS_TOKEN_GUARD_DENY',
            userId,
            status: AuditLogStatus.FAILURE,
            ipAddress: request.ip,
            userAgent: request.headers['user-agent'] as string,
            errorMessage: `Absolute session lifetime exceeded for session ${sessionId}. Session created at: ${sessionCreatedAt.toISOString()}`,
            details: {
              reason: 'ABSOLUTE_SESSION_LIFETIME_EXCEEDED_FROM_REDIS',
              sessionId,
              sessionCreatedAt: sessionCreatedAt.toISOString()
            } as Prisma.JsonObject
          })
          await this.tokenService.invalidateSession(sessionId, 'ABSOLUTE_LIFETIME_EXCEEDED')
          throw AbsoluteSessionLifetimeExceededException
        }
      } else {
        this.auditLogService.recordAsync({
          action: 'ACCESS_TOKEN_GUARD_DENY',
          userId,
          status: AuditLogStatus.FAILURE,
          ipAddress: request.ip,
          userAgent: request.headers['user-agent'] as string,
          errorMessage: `Session ${sessionId} is missing createdAt field in Redis. Could indicate data issue or remote revocation. `,
          details: { reason: 'SESSION_MISSING_CREATED_AT_IN_REDIS', sessionId } as Prisma.JsonObject
        })
        throw RemoteSessionRevokedException
      }

      await this.redisService.hset(sessionKey, 'lastActiveAt', new Date().toISOString())

      return true
    } catch (error) {
      const userIdFromToken = decodedAccessToken?.userId
      this.auditLogService.recordAsync({
        action: 'ACCESS_TOKEN_GUARD_CATCH_BLOCK',
        userId: userIdFromToken,
        status: AuditLogStatus.FAILURE,
        ipAddress: request.ip,
        userAgent: request.headers['user-agent'] as string,
        errorMessage: `Error in AccessTokenGuard catch block: ${error?.constructor?.name} - ${error instanceof Error ? error.message : 'Unknown error'}`,
        details: {
          originalErrorName: error?.constructor?.name,
          originalErrorMessage: error instanceof Error ? error.message : 'Unknown error',
          originalErrorStack: error instanceof Error ? error.stack : undefined,
          decodedAccessTokenBeforeErrorString: JSON.stringify(decodedAccessToken)
        } as Prisma.JsonObject
      })

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
        error instanceof ApiException &&
        (error.message === AbsoluteSessionLifetimeExceededException.message ||
          error.message === SessionNotFoundException.message ||
          error.message === RemoteSessionRevokedException.message ||
          error.message === InvalidAccessTokenException.message ||
          error.message === MismatchedSessionTokenException.message ||
          error.message === InvalidDeviceException.message)
      ) {
        throw error
      }

      this.auditLogService.recordAsync({
        action: 'ACCESS_TOKEN_GUARD_DENY',
        userId: userIdFromToken,
        status: AuditLogStatus.FAILURE,
        ipAddress: request.ip,
        userAgent: request.headers['user-agent'] as string,
        errorMessage: error instanceof Error ? error.message : 'Invalid or expired access token.',
        details
      })
      throw new UnauthorizedException('Error.Auth.Token.InvalidOrExpiredAccessToken')
    }
  }
}

const MissingAccessTokenException = new UnauthorizedException('Error.Auth.Token.MissingAccessToken')
