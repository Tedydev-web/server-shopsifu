import { Injectable, Logger } from '@nestjs/common'
import { JwtService } from '@nestjs/jwt'
import envConfig from 'src/shared/config'
import { AccessTokenPayload, AccessTokenPayloadCreate } from 'src/shared/types/jwt.type'
import { v4 as uuidv4 } from 'uuid'
import { Request, Response } from 'express'
import { Prisma } from '@prisma/client'
import { DeviceService } from './device.service'
import { PrismaTransactionClient } from 'src/shared/repositories/base.repository'
import { RedisService } from 'src/shared/providers/redis/redis.service'
import { REDIS_KEY_PREFIX } from 'src/shared/constants/redis.constants'
import ms from 'ms'
import { AuditLogService, AuditLogStatus } from 'src/routes/audit-log/audit-log.service'

interface CookieConfig {
  name: string
  path: string
  domain?: string
  maxAge: number
  httpOnly: boolean
  secure: boolean
  sameSite: 'lax' | 'strict' | 'none' | boolean
}

@Injectable()
export class TokenService {
  private readonly logger = new Logger(TokenService.name)

  constructor(
    private readonly jwtService: JwtService,
    private readonly deviceService: DeviceService,
    private readonly redisService: RedisService,
    private readonly auditLogService: AuditLogService
  ) {}

  signAccessToken(payload: Omit<AccessTokenPayloadCreate, 'exp' | 'iat'>) {
    this.logger.debug(`Signing access token for user ${payload.userId}, session ${payload.sessionId}`)
    return this.jwtService.sign(payload, {
      secret: envConfig.ACCESS_TOKEN_SECRET,
      expiresIn: envConfig.ACCESS_TOKEN_EXPIRES_IN,
      algorithm: 'HS256'
    })
  }

  signShortLivedToken(payload: Omit<AccessTokenPayloadCreate, 'exp' | 'iat'>) {
    this.logger.debug(
      `Signing short-lived access token for testing purposes: userId=${payload.userId}, session ${payload.sessionId}`
    )
    return this.jwtService.sign(payload, {
      secret: envConfig.ACCESS_TOKEN_SECRET,
      expiresIn: '30s',
      algorithm: 'HS256'
    })
  }

  verifyAccessToken(token: string): Promise<AccessTokenPayload> {
    return this.jwtService.verifyAsync(token, {
      secret: envConfig.ACCESS_TOKEN_SECRET
    })
  }

  extractTokenFromRequest(req: Request): string | null {
    return req.cookies?.[envConfig.cookie.accessToken.name] || this.extractTokenFromHeader(req)
  }

  extractRefreshTokenFromRequest(req: Request): string | null {
    return req.cookies?.[envConfig.cookie.refreshToken.name] || req.body?.refreshToken
  }

  private _setCookie(
    res: Response,
    name: string,
    value: string,
    config: Omit<CookieConfig, 'name'>,
    effectiveMaxAge?: number
  ) {
    const maxAgeToUse = effectiveMaxAge ?? config.maxAge
    if (value && maxAgeToUse > 0) {
      res.cookie(name, value, {
        path: config.path,
        domain: config.domain,
        maxAge: maxAgeToUse,
        httpOnly: config.httpOnly,
        secure: config.secure,
        sameSite: config.sameSite
      })
      this.logger.debug(`${name} cookie set successfully with maxAge: ${maxAgeToUse}`)
    } else {
      this.logger.warn(`res.cookie SKIPPED for ${name}. Reason:`, !value ? `${name} missing` : 'MaxAge not positive')
    }
  }

  setTokenCookies(res: Response, accessToken: string, refreshToken: string, maxAgeForRefreshTokenCookie?: number) {
    const accessTokenConfig = envConfig.cookie.accessToken
    const refreshTokenConfig = envConfig.cookie.refreshToken

    this._setCookie(res, accessTokenConfig.name, accessToken, accessTokenConfig)
    this._setCookie(res, refreshTokenConfig.name, refreshToken, refreshTokenConfig, maxAgeForRefreshTokenCookie)
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

    res.clearCookie(csrfTokenConfig.name, {
      domain: csrfTokenConfig.domain,
      path: csrfTokenConfig.path,
      httpOnly: csrfTokenConfig.httpOnly,
      secure: csrfTokenConfig.secure,
      sameSite: csrfTokenConfig.sameSite
    })

    this.logger.debug('All token cookies cleared successfully')
  }

  private extractTokenFromHeader(req: Request): string | null {
    const [type, tokenValue] = req.headers.authorization?.split(' ') || []
    return type === 'Bearer' ? tokenValue : null
  }

  async generateTokens(
    params: Omit<AccessTokenPayloadCreate, 'jti'>,
    _prismaTx?: PrismaTransactionClient,
    rememberMe?: boolean
  ) {
    const { userId, deviceId, roleId, roleName, sessionId } = params
    this.logger.debug(
      `Generating tokens for user ${userId}, device ${deviceId}, session ${sessionId}, rememberMe: ${!!rememberMe}`
    )

    const accessTokenJti = uuidv4()
    const accessToken = this.signAccessToken({
      userId,
      deviceId,
      roleId,
      roleName,
      sessionId,
      jti: accessTokenJti
    })

    const refreshTokenJti = uuidv4()

    let refreshTokenExpiresInMs: number
    if (rememberMe) {
      refreshTokenExpiresInMs = envConfig.REMEMBER_ME_REFRESH_TOKEN_COOKIE_MAX_AGE
    } else {
      refreshTokenExpiresInMs = envConfig.REFRESH_TOKEN_COOKIE_MAX_AGE
    }
    const refreshTokenExpiresInSeconds = Math.floor(refreshTokenExpiresInMs / 1000)

    await this.redisService.set(
      `${REDIS_KEY_PREFIX.REFRESH_TOKEN_JTI_TO_SESSION}${refreshTokenJti}`,
      sessionId,
      refreshTokenExpiresInSeconds
    )

    const sessionKey = `${REDIS_KEY_PREFIX.SESSION_DETAILS}${sessionId}`
    await this.redisService.hset(sessionKey, {
      currentAccessTokenJti: accessTokenJti,
      currentRefreshTokenJti: refreshTokenJti
    })
    const sessionTtl = await this.redisService.ttl(sessionKey)
    if (sessionTtl < 0 || sessionTtl < refreshTokenExpiresInSeconds) {
      await this.redisService.expire(sessionKey, Math.floor(envConfig.ABSOLUTE_SESSION_LIFETIME_MS / 1000))
    }

    return {
      accessToken,
      refreshToken: refreshTokenJti,
      maxAgeForRefreshTokenCookie: refreshTokenExpiresInMs,
      accessTokenJti
    }
  }

  async markRefreshTokenJtiAsUsed(refreshTokenJti: string, sessionId: string, ttlSeconds?: number) {
    this.logger.debug(`Marking refresh token JTI as used (blacklisting): ${refreshTokenJti}`)
    await this.redisService.set(
      `${REDIS_KEY_PREFIX.REFRESH_TOKEN_BLACKLIST}${refreshTokenJti}`,
      'revoked:used',
      ttlSeconds
    )
    await this.redisService.del(`${REDIS_KEY_PREFIX.REFRESH_TOKEN_JTI_TO_SESSION}${refreshTokenJti}`)

    const sessionDetails = await this.redisService.hgetall(`${REDIS_KEY_PREFIX.SESSION_DETAILS}${sessionId}`)
    if (sessionDetails && sessionDetails.deviceId) {
      await this.redisService.srem(
        `${REDIS_KEY_PREFIX.DEVICE_REFRESH_TOKENS}${sessionDetails.deviceId}`,
        refreshTokenJti
      )
    }
  }

  async invalidateRefreshTokenJti(refreshTokenJti: string, sessionId: string) {
    this.logger.debug(`Invalidating refresh token JTI: ${refreshTokenJti}`)
    const rtKey = `${REDIS_KEY_PREFIX.REFRESH_TOKEN_JTI_TO_SESSION}${refreshTokenJti}`
    const ttl = await this.redisService.ttl(rtKey)
    await this.redisService.set(
      `${REDIS_KEY_PREFIX.REFRESH_TOKEN_BLACKLIST}${refreshTokenJti}`,
      'revoked:logout',
      ttl > 0 ? ttl : ms(envConfig.REFRESH_TOKEN_EXPIRES_IN) / 1000
    )
    await this.redisService.del(rtKey)

    const sessionDetails = await this.redisService.hgetall(`${REDIS_KEY_PREFIX.SESSION_DETAILS}${sessionId}`)
    if (sessionDetails && sessionDetails.deviceId) {
      await this.redisService.srem(
        `${REDIS_KEY_PREFIX.DEVICE_REFRESH_TOKENS}${sessionDetails.deviceId}`,
        refreshTokenJti
      )
    }
  }

  async invalidateAccessTokenJti(accessTokenJti: string, accessTokenExp: number) {
    this.logger.debug(`Invalidating access token JTI: ${accessTokenJti}`)
    const nowInSeconds = Math.floor(Date.now() / 1000)
    const ttl = accessTokenExp - nowInSeconds
    if (ttl > 0) {
      await this.redisService.set(`${REDIS_KEY_PREFIX.ACCESS_TOKEN_BLACKLIST}${accessTokenJti}`, 'revoked', ttl)
    }
  }

  async findSessionIdByRefreshTokenJti(refreshTokenJti: string): Promise<string | null> {
    this.logger.debug(`Finding sessionId by refresh token JTI: ${refreshTokenJti}`)
    return this.redisService.get(`${REDIS_KEY_PREFIX.REFRESH_TOKEN_JTI_TO_SESSION}${refreshTokenJti}`)
  }

  async isRefreshTokenJtiBlacklisted(refreshTokenJti: string): Promise<boolean> {
    const result = await this.redisService.exists(`${REDIS_KEY_PREFIX.REFRESH_TOKEN_BLACKLIST}${refreshTokenJti}`)
    return result === 1
  }

  async isAccessTokenJtiBlacklisted(accessTokenJti: string): Promise<boolean> {
    const result = await this.redisService.exists(`${REDIS_KEY_PREFIX.ACCESS_TOKEN_BLACKLIST}${accessTokenJti}`)
    return result === 1
  }

  async refreshTokenSilently(
    clientRefreshTokenJti: string,
    userAgent: string,
    ip: string
  ): Promise<{
    accessToken: string
    refreshToken?: string
    maxAgeForRefreshTokenCookie?: number
  } | null> {
    this.logger.debug(`Attempting to silently refresh token with JTI: ${clientRefreshTokenJti}`)
    const auditLogDetails: Prisma.JsonObject = {
      refreshTokenJtiProvided: clientRefreshTokenJti,
      userAgent,
      ip
    }

    if (await this.isRefreshTokenJtiBlacklisted(clientRefreshTokenJti)) {
      this.logger.warn(`Silent refresh failed: Refresh token JTI ${clientRefreshTokenJti} is blacklisted.`)
      auditLogDetails.reason = 'REFRESH_TOKEN_JTI_BLACKLISTED'
      this.auditLogService.recordAsync({
        action: 'REFRESH_TOKEN_SILENTLY_FAIL',
        status: AuditLogStatus.FAILURE,
        ipAddress: ip,
        userAgent,
        errorMessage: 'Refresh token JTI is blacklisted.',
        details: auditLogDetails
      })
      return null
    }

    const sessionId = await this.findSessionIdByRefreshTokenJti(clientRefreshTokenJti)
    if (!sessionId) {
      this.logger.warn(`Silent refresh failed: No session found for refresh token JTI ${clientRefreshTokenJti}.`)
      auditLogDetails.reason = 'SESSION_NOT_FOUND_FOR_RT_JTI'
      this.auditLogService.recordAsync({
        action: 'REFRESH_TOKEN_SILENTLY_FAIL',
        status: AuditLogStatus.FAILURE,
        ipAddress: ip,
        userAgent,
        errorMessage: 'No session found for the provided refresh token JTI.',
        details: auditLogDetails
      })
      return null
    }
    auditLogDetails.sessionId = sessionId

    const sessionKey = `${REDIS_KEY_PREFIX.SESSION_DETAILS}${sessionId}`
    const sessionDetails = await this.redisService.hgetall(sessionKey)

    if (!sessionDetails || Object.keys(sessionDetails).length === 0) {
      this.logger.warn(`Silent refresh failed: Session ${sessionId} not found or empty.`)
      await this.invalidateRefreshTokenJti(clientRefreshTokenJti, sessionId)
      auditLogDetails.reason = 'SESSION_EMPTY_OR_NOT_FOUND_IN_REDIS'
      this.auditLogService.recordAsync({
        action: 'REFRESH_TOKEN_SILENTLY_FAIL',
        userId: parseInt(sessionDetails?.userId, 10) || undefined,
        status: AuditLogStatus.FAILURE,
        ipAddress: ip,
        userAgent,
        errorMessage: 'Session not found in Redis or is empty.',
        details: auditLogDetails
      })
      return null
    }
    auditLogDetails.sessionUserId = parseInt(sessionDetails.userId, 10)
    auditLogDetails.sessionDeviceId = parseInt(sessionDetails.deviceId, 10)

    if (sessionDetails.currentRefreshTokenJti !== clientRefreshTokenJti) {
      this.logger.warn(
        `Silent refresh failed: Provided RT JTI ${clientRefreshTokenJti} does not match current RT JTI ${sessionDetails.currentRefreshTokenJti} in session ${sessionId}. Potential token theft or replay.`
      )
      await this.invalidateSession(sessionId, 'SUSPECTED_TOKEN_THEFT_ON_REFRESH')
      auditLogDetails.reason = 'REFRESH_TOKEN_JTI_MISMATCH'
      auditLogDetails.suspectedCurrentSessionRtJti = sessionDetails.currentRefreshTokenJti
      this.auditLogService.recordAsync({
        action: 'REFRESH_TOKEN_SILENTLY_FAIL',
        userId: parseInt(sessionDetails.userId, 10),
        status: AuditLogStatus.FAILURE,
        ipAddress: ip,
        userAgent,
        errorMessage: 'Provided refresh token JTI does not match the current one in session. Session invalidated.',
        details: auditLogDetails
      })
      return null
    }

    const expectedUserAgentFingerprint = this.deviceService.basicDeviceFingerprint(sessionDetails.userAgent)
    const currentUserAgentFingerprint = this.deviceService.basicDeviceFingerprint(userAgent)
    if (expectedUserAgentFingerprint !== currentUserAgentFingerprint) {
      this.logger.warn(
        `Silent refresh failed for session ${sessionId}: User-Agent mismatch. Expected fingerprint: ${expectedUserAgentFingerprint}, got: ${currentUserAgentFingerprint}`
      )
      auditLogDetails.reason = 'USER_AGENT_MISMATCH'
      auditLogDetails.expectedUserAgentFingerprint = expectedUserAgentFingerprint
      auditLogDetails.currentUserAgentFingerprint = currentUserAgentFingerprint
      this.auditLogService.recordAsync({
        action: 'REFRESH_TOKEN_SILENTLY_FAIL',
        userId: parseInt(sessionDetails.userId, 10),
        status: AuditLogStatus.FAILURE,
        ipAddress: ip,
        userAgent,
        errorMessage: 'User-Agent mismatch during token refresh.',
        details: auditLogDetails
      })
      return null
    }

    const now = new Date()
    await this.redisService.hset(sessionKey, 'lastActiveAt', now.toISOString())
    this.logger.debug(`Session ${sessionId} last active time updated.`)

    const newAccessTokenJti = uuidv4()
    const newAccessToken = this.signAccessToken({
      userId: parseInt(sessionDetails.userId, 10),
      deviceId: parseInt(sessionDetails.deviceId, 10),
      roleId: parseInt(sessionDetails.roleId, 10),
      roleName: sessionDetails.roleName,
      sessionId: sessionId,
      jti: newAccessTokenJti
    })
    await this.redisService.hset(sessionKey, 'currentAccessTokenJti', newAccessTokenJti)
    auditLogDetails.newAccessTokenJti = newAccessTokenJti

    const shouldRotateRefreshToken = true
    let newRefreshTokenJti: string | undefined = undefined
    let maxAgeForCookie: number | undefined = undefined

    if (shouldRotateRefreshToken) {
      this.logger.debug(`Rotating refresh token for session ${sessionId}. Old RT JTI: ${clientRefreshTokenJti}`)
      const oldRtKey = `${REDIS_KEY_PREFIX.REFRESH_TOKEN_JTI_TO_SESSION}${clientRefreshTokenJti}`
      const oldRtTtl = await this.redisService.ttl(oldRtKey)
      const blacklistTtl = oldRtTtl > 0 ? oldRtTtl : 300
      await this.markRefreshTokenJtiAsUsed(clientRefreshTokenJti, sessionId, blacklistTtl)

      newRefreshTokenJti = uuidv4()
      const rememberMe = sessionDetails.rememberMe === 'true'
      if (rememberMe) {
        maxAgeForCookie = Number(envConfig.REMEMBER_ME_REFRESH_TOKEN_COOKIE_MAX_AGE)
      } else {
        maxAgeForCookie = Number(envConfig.REFRESH_TOKEN_COOKIE_MAX_AGE)
      }
      const newRtTtlSeconds = maxAgeForCookie > 0 ? Math.floor(maxAgeForCookie / 1000) : 0

      if (newRtTtlSeconds > 0) {
        await this.redisService.set(
          `${REDIS_KEY_PREFIX.REFRESH_TOKEN_JTI_TO_SESSION}${newRefreshTokenJti}`,
          sessionId,
          newRtTtlSeconds
        )
      } else {
        await this.redisService.set(
          `${REDIS_KEY_PREFIX.REFRESH_TOKEN_JTI_TO_SESSION}${newRefreshTokenJti}`,
          sessionId,
          Math.floor(envConfig.ABSOLUTE_SESSION_LIFETIME_MS / 1000)
        )
      }

      await this.redisService.hset(sessionKey, 'currentRefreshTokenJti', newRefreshTokenJti)
      if (sessionDetails.deviceId) {
        await this.redisService.sadd(
          `${REDIS_KEY_PREFIX.DEVICE_REFRESH_TOKENS}${sessionDetails.deviceId}`,
          newRefreshTokenJti
        )
      }
      this.logger.log(`Rotated Refresh Token for session ${sessionId}. New RT JTI: ${newRefreshTokenJti}`)
      auditLogDetails.rotatedToNewRefreshTokenJti = newRefreshTokenJti
    } else {
      newRefreshTokenJti = clientRefreshTokenJti
      maxAgeForCookie =
        parseInt(sessionDetails.maxAgeForRefreshTokenCookie, 10) || envConfig.REFRESH_TOKEN_COOKIE_MAX_AGE
      this.logger.debug(
        `Refresh token rotation is OFF. Reusing RT JTI: ${clientRefreshTokenJti} for session ${sessionId}`
      )
    }

    this.auditLogService.recordAsync({
      action: 'REFRESH_TOKEN_SILENTLY_SUCCESS',
      userId: parseInt(sessionDetails.userId, 10),
      status: AuditLogStatus.SUCCESS,
      ipAddress: ip,
      userAgent,
      details: {
        ...auditLogDetails,
        accessToken: newAccessToken,
        refreshToken: shouldRotateRefreshToken ? newRefreshTokenJti : undefined,
        maxAgeForRefreshTokenCookie: shouldRotateRefreshToken ? maxAgeForCookie : undefined
      }
    })

    return {
      accessToken: newAccessToken,
      refreshToken: shouldRotateRefreshToken ? newRefreshTokenJti : undefined,
      maxAgeForRefreshTokenCookie: shouldRotateRefreshToken ? maxAgeForCookie : undefined
    }
  }

  async invalidateSession(sessionId: string, reason: string = 'UNKNOWN') {
    this.logger.warn(`Invalidating session ${sessionId} due to: ${reason}`)
    const sessionKey = `${REDIS_KEY_PREFIX.SESSION_DETAILS}${sessionId}`
    const sessionDetails = await this.redisService.hgetall(sessionKey)

    if (!sessionDetails || Object.keys(sessionDetails).length === 0) {
      this.logger.warn(`Attempted to invalidate a non-existent session: ${sessionId}`)
      return
    }

    const userId = parseInt(sessionDetails.userId, 10)
    const currentAccessTokenJti = sessionDetails.currentAccessTokenJti
    const currentRefreshTokenJti = sessionDetails.currentRefreshTokenJti

    if (currentAccessTokenJti) {
      await this.invalidateAccessTokenJti(currentAccessTokenJti, Math.floor(Date.now() / 1000) + 60)
    }
    if (currentRefreshTokenJti) {
      await this.invalidateRefreshTokenJti(currentRefreshTokenJti, sessionId)
    }

    const deletePipeline = this.redisService.client.pipeline()
    if (userId) {
      deletePipeline.srem(`${REDIS_KEY_PREFIX.USER_SESSIONS}${userId}`, sessionId)
    }
    deletePipeline.del(sessionKey)
    await deletePipeline.exec()

    this.logger.log(`Session ${sessionId} and associated tokens have been invalidated.`)
  }

  async invalidateAllUserSessions(userId: number, reason: string = 'UNKNOWN_BULK_INVALIDATION') {
    this.logger.warn(`Invalidating all sessions for user ${userId} due to: ${reason}`)
    const userSessionsKey = `${REDIS_KEY_PREFIX.USER_SESSIONS}${userId}`
    const sessionIds = await this.redisService.smembers(userSessionsKey)

    if (sessionIds && sessionIds.length > 0) {
      const pipeline = this.redisService.client.pipeline()
      for (const sessionId of sessionIds) {
        const sessionKey = `${REDIS_KEY_PREFIX.SESSION_DETAILS}${sessionId}`
        const currentRefreshTokenJti = await this.redisService.hget(sessionKey, 'currentRefreshTokenJti')
        if (currentRefreshTokenJti) {
          const rtKey = `${REDIS_KEY_PREFIX.REFRESH_TOKEN_JTI_TO_SESSION}${currentRefreshTokenJti}`
          const ttl = await this.redisService.ttl(rtKey)
          const blacklistTtlSeconds = ttl > 0 ? ttl : Math.floor(ms(envConfig.REFRESH_TOKEN_EXPIRES_IN) / 1000)
          if (blacklistTtlSeconds > 0) {
            pipeline.set(
              `${REDIS_KEY_PREFIX.REFRESH_TOKEN_BLACKLIST}${currentRefreshTokenJti}`,
              `revoked:${reason}`,
              'EX',
              blacklistTtlSeconds
            )
          } else {
            pipeline.set(`${REDIS_KEY_PREFIX.REFRESH_TOKEN_BLACKLIST}${currentRefreshTokenJti}`, `revoked:${reason}`)
          }
          pipeline.del(rtKey)
        }

        // const currentAccessTokenJti = await this.redisService.hget(sessionKey, 'currentAccessTokenJti') // Commented out/removed as AT JTI handling is through session deletion
        // if (currentAccessTokenJti) {
        // } // Removed empty block

        pipeline.del(sessionKey)
      }
      pipeline.del(userSessionsKey)
      await pipeline.exec()
      this.logger.log(`Invalidated ${sessionIds.length} sessions for user ${userId}.`)
    } else {
      this.logger.log(`No active sessions found for user ${userId} to invalidate.`)
    }
  }
}
