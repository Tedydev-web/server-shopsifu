import { Injectable, Logger, HttpStatus } from '@nestjs/common'
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
import {
  InvalidRefreshTokenException,
  SessionNotFoundException,
  AbsoluteSessionLifetimeExceededException,
  DeviceMismatchException
} from '../auth.error'

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
      expiresIn: envConfig.ACCESS_TOKEN_EXPIRY,
      jwtid: payload.jti
    })
  }

  signShortLivedToken(payload: Omit<AccessTokenPayloadCreate, 'exp' | 'iat'>) {
    this.logger.debug(
      `Signing short-lived access token for testing purposes: userId=${payload.userId}, session ${payload.sessionId}`
    )
    return this.jwtService.sign(payload, {
      secret: envConfig.ACCESS_TOKEN_SECRET,
      expiresIn: '5m',
      jwtid: payload.jti
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

  setTokenCookies(
    res: Response,
    accessToken: string,
    refreshToken: string,
    maxAgeForRefreshTokenCookie?: number,
    isRefreshTokenOnly?: boolean
  ) {
    const accessTokenConfig = envConfig.cookie.accessToken
    const refreshTokenConfig = envConfig.cookie.refreshToken

    if (!isRefreshTokenOnly) {
      this._setCookie(res, accessTokenConfig.name, accessToken, accessTokenConfig)
    }
    this._setCookie(res, refreshTokenConfig.name, refreshToken, refreshTokenConfig, maxAgeForRefreshTokenCookie)
  }

  clearTokenCookies(res: Response) {
    const accessTokenConfig = envConfig.cookie.accessToken
    const refreshTokenConfig = envConfig.cookie.refreshToken

    this.logger.debug(`Clearing access token cookie (${accessTokenConfig.name})`)
    res.clearCookie(accessTokenConfig.name, {
      path: accessTokenConfig.path,
      domain: accessTokenConfig.domain,
      httpOnly: accessTokenConfig.httpOnly,
      secure: accessTokenConfig.secure,
      sameSite: accessTokenConfig.sameSite
    })

    this.logger.debug(`Clearing refresh token cookie (${refreshTokenConfig.name})`)
    res.clearCookie(refreshTokenConfig.name, {
      path: refreshTokenConfig.path,
      domain: refreshTokenConfig.domain,
      httpOnly: refreshTokenConfig.httpOnly,
      secure: refreshTokenConfig.secure,
      sameSite: refreshTokenConfig.sameSite
    })
  }

  clearSltCookie(res: Response) {
    const sltTokenConfig = envConfig.cookie.sltToken
    if (sltTokenConfig) {
      this.logger.debug(`Clearing SLT token cookie (${sltTokenConfig.name})`)
      res.clearCookie(sltTokenConfig.name, {
        path: sltTokenConfig.path,
        domain: sltTokenConfig.domain,
        httpOnly: sltTokenConfig.httpOnly,
        secure: sltTokenConfig.secure,
        sameSite: sltTokenConfig.sameSite
      })
    } else {
      this.logger.warn('SLT token cookie configuration not found, cannot clear SLT cookie.')
    }
  }

  public extractTokenFromHeader(req: Request): string | null {
    const [type, token] = req.headers.authorization?.split(' ') ?? []
    return type === 'Bearer' ? token : null
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
      refreshTokenExpiresInMs = envConfig.cookie.REMEMBER_ME_REFRESH_TOKEN_COOKIE_MAX_AGE
    } else {
      refreshTokenExpiresInMs = envConfig.cookie.REFRESH_TOKEN_COOKIE_MAX_AGE
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
    const refreshTokenConfiguredExpirySeconds = ms(envConfig.REFRESH_TOKEN_EXPIRY) / 1000
    if (sessionTtl < refreshTokenConfiguredExpirySeconds) {
      const remainingAbsoluteLife = envConfig.ABSOLUTE_SESSION_LIFETIME_MS - Date.now()
      await this.redisService.expire(sessionKey, Math.floor(remainingAbsoluteLife / 1000))
    }

    return {
      accessToken,
      refreshTokenJti: refreshTokenJti,
      maxAgeForRefreshTokenCookie: refreshTokenExpiresInMs,
      accessTokenJti
    }
  }

  async markRefreshTokenJtiAsUsed(refreshTokenJti: string, sessionId: string, ttlSeconds?: number) {
    this.logger.debug(`Marking refresh token JTI as used (blacklisting): ${refreshTokenJti}`)
    const key = `${REDIS_KEY_PREFIX.USED_REFRESH_TOKEN_JTI}${refreshTokenJti}`
    const effectiveTtl = ttlSeconds && ttlSeconds > 0 ? ttlSeconds : ms(envConfig.REFRESH_TOKEN_EXPIRY) / 1000
    await this.redisService.set(key, sessionId, Math.ceil(effectiveTtl))
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
      ttl > 0 ? ttl : ms(envConfig.REFRESH_TOKEN_EXPIRY) / 1000
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
        maxAgeForCookie = Number(envConfig.cookie.REMEMBER_ME_REFRESH_TOKEN_COOKIE_MAX_AGE)
      } else {
        maxAgeForCookie = Number(envConfig.cookie.REFRESH_TOKEN_COOKIE_MAX_AGE)
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
        parseInt(sessionDetails.maxAgeForRefreshTokenCookie, 10) || envConfig.cookie.REFRESH_TOKEN_COOKIE_MAX_AGE
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

  private async _addSessionInvalidationToPipeline(
    pipeline: ReturnType<RedisService['client']['pipeline']>,
    sessionId: string,
    reason: string = 'UNKNOWN'
  ) {
    const sessionKey = `${REDIS_KEY_PREFIX.SESSION_DETAILS}${sessionId}`
    const sessionDetails = await this.redisService.hgetall(sessionKey)

    if (Object.keys(sessionDetails).length === 0) {
      this.logger.warn(
        `[TokenService] Attempted to invalidate non-existent or empty session ${sessionId}. Reason: ${reason}. Skipping Redis operations for this session.`
      )
      return
    }

    const userId = sessionDetails.userId
    const currentRefreshTokenJti = sessionDetails.currentRefreshTokenJti
    const currentAccessTokenJti = sessionDetails.currentAccessTokenJti
    const accessTokenExp = sessionDetails.accessTokenExp ? parseInt(sessionDetails.accessTokenExp, 10) : null

    pipeline.del(sessionKey)
    if (userId) {
      const userSessionsKey = `${REDIS_KEY_PREFIX.USER_SESSIONS}${userId}`
      pipeline.srem(userSessionsKey, sessionId)
    }
    if (currentRefreshTokenJti) {
      const refreshTokenJtiToSessionKey = `${REDIS_KEY_PREFIX.REFRESH_TOKEN_JTI_TO_SESSION}${currentRefreshTokenJti}`
      pipeline.del(refreshTokenJtiToSessionKey)
      const rtBlacklistKey = `${REDIS_KEY_PREFIX.USED_REFRESH_TOKEN_JTI}${currentRefreshTokenJti}`
      const rtExpirySeconds = ms(envConfig.REFRESH_TOKEN_EXPIRY) / 1000
      pipeline.set(rtBlacklistKey, sessionId, 'EX', Math.ceil(rtExpirySeconds))
    }

    if (currentAccessTokenJti && accessTokenExp) {
      const nowInSeconds = Math.floor(Date.now() / 1000)
      if (accessTokenExp > nowInSeconds) {
        const ttl = accessTokenExp - nowInSeconds
        const accessTokenJtiBlacklistKey = `${REDIS_KEY_PREFIX.ACCESS_TOKEN_BLACKLIST}${currentAccessTokenJti}`
        pipeline.set(accessTokenJtiBlacklistKey, `INVALIDATED:${reason}`, 'EX', ttl)
      }
    }

    this.logger.log(
      `[TokenService] Session ${sessionId} (User: ${userId || 'N/A'}) marked for invalidation in pipeline. Reason: ${reason}.`
    )
  }

  async invalidateSession(sessionId: string, reason: string = 'UNKNOWN') {
    const pipeline = this.redisService.client.pipeline()
    await this._addSessionInvalidationToPipeline(pipeline, sessionId, reason)
    const results = await pipeline.exec()
    if (results) {
      results.forEach(([err, result], index) => {
        if (err) {
          this.logger.error(`Error in invalidateSession pipeline (command ${index}): ${err.message}`)
        }
      })
    } else {
      this.logger.error('invalidateSession pipeline execution returned null')
    }

    this.logger.log(`[TokenService] Session ${sessionId} invalidation process completed. Reason: ${reason}.`)
  }

  async invalidateAllUserSessions(userId: number, reason: string = 'UNKNOWN_BULK_INVALIDATION') {
    const userSessionsKey = `${REDIS_KEY_PREFIX.USER_SESSIONS}${userId}`
    const sessionIds = await this.redisService.smembers(userSessionsKey)
    let invalidatedCount = 0

    if (sessionIds.length === 0) {
      this.logger.debug(`No active sessions found for user ${userId} to invalidate.`)
      return { invalidatedCount }
    }

    const pipeline = this.redisService.client.pipeline()
    const jtisToBlacklist: Array<{ jti: string; exp: number }> = []

    for (const sessionId of sessionIds) {
      const sessionDetailsKey = `${REDIS_KEY_PREFIX.SESSION_DETAILS}${sessionId}`
      const sessionData = await this.redisService.hgetall(sessionDetailsKey)

      if (sessionData && sessionData.currentRefreshTokenJti && sessionData.currentAccessTokenJti) {
        const refreshTokenJti = sessionData.currentRefreshTokenJti
        const accessTokenJti = sessionData.currentAccessTokenJti
        const accessTokenExp = Number(sessionData.accessTokenExp) // Assuming accessTokenExp is stored

        // Add JTI to a list for blacklisting after removing session details
        if (accessTokenJti && accessTokenExp && accessTokenExp * 1000 > Date.now()) {
          jtisToBlacklist.push({ jti: accessTokenJti, exp: accessTokenExp })
        }
        // For refresh tokens, they are typically long-lived; blacklisting their JTI is key.
        // We don't necessarily need their expiry here for blacklisting, as the JTI itself is the target.
        // However, if we were to store a TTL with the blacklist entry, we'd need it.
        // For now, direct blacklisting of JTI (e.g. via SADD to a blacklist set or a key with a long TTL)

        pipeline.del(sessionDetailsKey) // Delete session details from Redis
        pipeline.srem(userSessionsKey, sessionId) // Remove session ID from user's set of sessions

        // Mark refresh token JTI as used (blacklisted)
        const rtBlacklistKey = `${REDIS_KEY_PREFIX.USED_REFRESH_TOKEN_JTI}${refreshTokenJti}`
        const rtExpirySeconds = ms(envConfig.REFRESH_TOKEN_EXPIRY) / 1000 // Use configured TTL
        pipeline.set(rtBlacklistKey, sessionId, 'EX', Math.ceil(rtExpirySeconds))

        invalidatedCount++
        this.logger.log(`Session ${sessionId} for user ${userId} marked for invalidation. Reason: ${reason}`)
      } else {
        this.logger.warn(
          `Session data incomplete or missing for session ${sessionId}, user ${userId}. Removing from set.`
        )
        pipeline.srem(userSessionsKey, sessionId) // Clean up inconsistent entry
      }
    }

    // Blacklist access tokens
    for (const item of jtisToBlacklist) {
      const blacklistKey = `${REDIS_KEY_PREFIX.ACCESS_TOKEN_BLACKLIST}${item.jti}`
      const ttl = item.exp - Math.floor(Date.now() / 1000)
      if (ttl > 0) {
        pipeline.set(blacklistKey, 'invalidated', 'EX', ttl)
      }
    }

    await pipeline.exec()

    if (invalidatedCount > 0) {
      this.logger.log(`Successfully invalidated ${invalidatedCount} sessions for user ${userId}. Reason: ${reason}`)
      this.auditLogService.recordAsync({
        action: 'BULK_SESSION_INVALIDATION',
        userId,
        status: AuditLogStatus.SUCCESS,
        details: { invalidatedCount, reason } as Prisma.JsonObject
      })
    }
    return { invalidatedCount }
  }
}
