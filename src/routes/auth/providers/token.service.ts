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
import {
  InvalidRefreshTokenException,
  ExpiredRefreshTokenException,
  RefreshTokenAlreadyUsedException,
  RefreshTokenNotFoundException,
  RefreshTokenSessionInvalidException,
  RefreshTokenDeviceMismatchException
} from 'src/routes/auth/auth.error'

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
      sameSite: accessTokenConfig.sameSite as 'lax' | 'strict' | 'none' | boolean
    })

    this.logger.debug(`Clearing refresh token cookie (${refreshTokenConfig.name})`)
    res.clearCookie(refreshTokenConfig.name, {
      path: refreshTokenConfig.path,
      domain: refreshTokenConfig.domain,
      httpOnly: refreshTokenConfig.httpOnly,
      secure: refreshTokenConfig.secure,
      sameSite: refreshTokenConfig.sameSite as 'lax' | 'strict' | 'none' | boolean
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
        sameSite: sltTokenConfig.sameSite as 'lax' | 'strict' | 'none' | boolean
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
    params: Omit<AccessTokenPayloadCreate, 'jti'> & { isDeviceTrustedInSession?: boolean },
    _prismaTx?: PrismaTransactionClient,
    rememberMe?: boolean
  ) {
    const { userId, deviceId, roleId, roleName, sessionId } = params
    this.logger.debug(
      `Generating tokens for user ${userId}, device ${deviceId}, session ${sessionId}, rememberMe: ${!!rememberMe}`
    )

    const accessTokenJti = uuidv4()
    const refreshTokenJti = uuidv4()

    const accessTokenPayloadToSign: Omit<AccessTokenPayloadCreate, 'exp' | 'iat'> = {
      ...params,
      jti: accessTokenJti,
      isDeviceTrustedInSession: params.isDeviceTrustedInSession ?? false
    }

    const accessToken = this.signAccessToken(accessTokenPayloadToSign)

    const decodedAccessToken = this.jwtService.decode(accessToken) as AccessTokenPayload
    const accessTokenExp = decodedAccessToken.exp

    let refreshTokenExpiresInMs: number
    if (rememberMe) {
      refreshTokenExpiresInMs = envConfig.REMEMBER_ME_REFRESH_TOKEN_COOKIE_MAX_AGE
    } else {
      refreshTokenExpiresInMs = envConfig.REFRESH_TOKEN_COOKIE_MAX_AGE
    }
    const refreshTokenExpiresInSeconds = Math.floor(refreshTokenExpiresInMs / 1000)

    this.logger.debug(
      `Calculated refreshTokenExpiresInSeconds: ${refreshTokenExpiresInSeconds} (from ${refreshTokenExpiresInMs}ms)`
    )

    await this.redisService.set(
      `${REDIS_KEY_PREFIX.REFRESH_TOKEN_JTI_TO_SESSION}${refreshTokenJti}`,
      sessionId,
      'EX',
      refreshTokenExpiresInSeconds
    )

    const sessionKey = `${REDIS_KEY_PREFIX.SESSION_DETAILS}${sessionId}`
    await this.redisService.hset(sessionKey, {
      currentAccessTokenJti: accessTokenJti,
      currentRefreshTokenJti: refreshTokenJti,
      accessTokenExp: accessTokenExp.toString()
    })
    const sessionTtl = await this.redisService.ttl(sessionKey)
    if (sessionTtl < 0 || sessionTtl < refreshTokenExpiresInSeconds) {
      const absoluteSessionLifetimeInSeconds = Math.floor(envConfig.ABSOLUTE_SESSION_LIFETIME_MS / 1000)
      this.logger.debug(
        `Calculated absoluteSessionLifetimeInSeconds for session ${sessionId}: ${absoluteSessionLifetimeInSeconds} (from ${envConfig.ABSOLUTE_SESSION_LIFETIME_MS}ms). Current TTL: ${sessionTtl}`
      )
      await this.redisService.expire(sessionKey, absoluteSessionLifetimeInSeconds)
    }

    return {
      accessToken,
      refreshTokenJti: refreshTokenJti,
      maxAgeForRefreshTokenCookie: refreshTokenExpiresInMs,
      accessTokenJti,
      accessTokenPayload: decodedAccessToken
    }
  }

  async markRefreshTokenJtiAsUsed(refreshTokenJti: string, sessionId: string, ttlSeconds?: number): Promise<boolean> {
    const usedKey = `${REDIS_KEY_PREFIX.USED_REFRESH_TOKEN_JTI}${refreshTokenJti}`
    const effectiveTtl = ttlSeconds ?? Math.floor(ms(envConfig.REFRESH_TOKEN_EXPIRES_IN) / 1000)

    this.logger.verbose(
      `Attempting to mark RT JTI ${refreshTokenJti} as used for session ${sessionId} with TTL ${effectiveTtl}s. Key: ${usedKey}`
    )
    // Set the value to the session ID that used it.
    // 'NX' ensures this is set only if the JTI hasn't been marked as used before.
    const result = await this.redisService.set(usedKey, sessionId, 'EX', effectiveTtl, 'NX')

    if (result === null) {
      // This means the key already existed (NX condition failed).
      this.logger.warn(
        `RT JTI ${refreshTokenJti} was already marked as used. Current session trying to mark: ${sessionId}. Associated session (if set by other): ${await this.redisService.get(usedKey)}.`
      )
      return false // Indicate that marking failed because it already existed
    }
    this.logger.verbose(`RT JTI ${refreshTokenJti} successfully marked as used for session ${sessionId}.`)
    return true // Indicate successful marking
  }

  async invalidateRefreshTokenJti(refreshTokenJti: string, sessionId: string) {
    this.logger.debug(`Invalidating refresh token JTI: ${refreshTokenJti}`)
    const rtKey = `${REDIS_KEY_PREFIX.REFRESH_TOKEN_JTI_TO_SESSION}${refreshTokenJti}`
    const ttl = await this.redisService.ttl(rtKey)
    await this.redisService.set(
      `${REDIS_KEY_PREFIX.REFRESH_TOKEN_BLACKLIST}${refreshTokenJti}`,
      `revoked:logout`,
      'EX',
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
      await this.redisService.set(`${REDIS_KEY_PREFIX.ACCESS_TOKEN_BLACKLIST}${accessTokenJti}`, 'revoked', 'EX', ttl)
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
    accessTokenPayload: AccessTokenPayload
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
      throw InvalidRefreshTokenException
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
      throw RefreshTokenNotFoundException
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
      throw RefreshTokenSessionInvalidException
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
      throw InvalidRefreshTokenException
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
      throw RefreshTokenDeviceMismatchException
    }

    const now = new Date()
    await this.redisService.hset(sessionKey, 'lastActiveAt', now.toISOString())
    this.logger.debug(`Session ${sessionId} last active time updated.`)

    const newAccessTokenJti = uuidv4()
    const nowTime = Math.floor(Date.now() / 1000) // For iat and exp calculation

    const accessTokenPayloadToSign: Omit<AccessTokenPayloadCreate, 'exp' | 'iat' | 'isDeviceTrustedInSession'> & {
      isDeviceTrustedInSession?: boolean
    } = {
      userId: parseInt(sessionDetails.userId, 10),
      deviceId: parseInt(sessionDetails.deviceId, 10),
      roleId: parseInt(sessionDetails.roleId, 10),
      roleName: sessionDetails.roleName,
      sessionId: sessionId,
      jti: newAccessTokenJti,
      // isDeviceTrustedInSession will be part of AccessTokenPayloadCreate, ensure it's included from sessionDetails
      isDeviceTrustedInSession: sessionDetails.isDeviceTrustedInSession === 'true'
    }

    const newAccessToken = this.signAccessToken(accessTokenPayloadToSign)

    const finalAccessTokenPayload: AccessTokenPayload = {
      ...accessTokenPayloadToSign,
      iat: nowTime,
      exp: nowTime + Math.floor(ms(envConfig.ACCESS_TOKEN_EXPIRES_IN) / 1000),
      // Ensure all fields from AccessTokenPayloadCreate are present
      isDeviceTrustedInSession: accessTokenPayloadToSign.isDeviceTrustedInSession ?? false
    }

    await this.redisService.hset(sessionKey, 'currentAccessTokenJti', newAccessTokenJti)

    const shouldRotateRefreshToken = true
    let newRefreshTokenJti: string | undefined = undefined
    let maxAgeForCookie: number | undefined = undefined

    if (shouldRotateRefreshToken) {
      this.logger.debug(`Rotating refresh token for session ${sessionId}. Old RT JTI: ${clientRefreshTokenJti}`)
      const oldRtKey = `${REDIS_KEY_PREFIX.REFRESH_TOKEN_JTI_TO_SESSION}${clientRefreshTokenJti}`
      const oldRtTtl = await this.redisService.ttl(oldRtKey)
      const blacklistTtl = oldRtTtl > 0 ? oldRtTtl : 300
      const markedSuccessfully = await this.markRefreshTokenJtiAsUsed(clientRefreshTokenJti, sessionId, blacklistTtl)

      if (!markedSuccessfully) {
        this.logger.warn(
          `Refresh token JTI ${clientRefreshTokenJti} for session ${sessionId} was already marked as used by another process. Aborting refresh.`
        )
        // This session is now potentially compromised or a race condition was lost.
        // Invalidate the session as a security measure if it wasn't already.
        await this.invalidateSession(sessionId, 'RT_JTI_ALREADY_USED_ON_REFRESH_ATTEMPT')
        throw RefreshTokenAlreadyUsedException // Specific exception for client
      }

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
          'EX',
          newRtTtlSeconds
        )
      } else {
        await this.redisService.set(
          `${REDIS_KEY_PREFIX.REFRESH_TOKEN_JTI_TO_SESSION}${newRefreshTokenJti}`,
          sessionId,
          'EX',
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
      maxAgeForRefreshTokenCookie: shouldRotateRefreshToken ? maxAgeForCookie : undefined,
      accessTokenPayload: finalAccessTokenPayload
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
      const usedRefreshTokenKey = `${REDIS_KEY_PREFIX.USED_REFRESH_TOKEN_JTI}${currentRefreshTokenJti}`
      const refreshTokenTTL = ms(envConfig.REFRESH_TOKEN_EXPIRES_IN) / 1000
      pipeline.set(usedRefreshTokenKey, sessionId, 'EX', refreshTokenTTL)
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

  async invalidateAllUserSessions(
    userId: number,
    reason: string = 'UNKNOWN_BULK_INVALIDATION',
    sessionIdToExclude?: string
  ): Promise<{ invalidatedCount: number }> {
    const userSessionsKey = `${REDIS_KEY_PREFIX.USER_SESSIONS}${userId}`
    const sessionIds = await this.redisService.smembers(userSessionsKey)

    if (!sessionIds || sessionIds.length === 0) {
      this.logger.log(`No active sessions found for user ${userId} to invalidate.`)
      return { invalidatedCount: 0 }
    }

    let invalidatedCount = 0
    const pipeline = this.redisService.client.pipeline()
    const sessionKeysToDelete: string[] = []
    const deviceSessionUpdates: Map<string, string[]> = new Map() // Key: deviceSessionKey, Value: array of sessionIds to SREM

    for (const sessionId of sessionIds) {
      if (sessionId === sessionIdToExclude) {
        this.logger.verbose(`Skipping excluded session ${sessionId} during bulk invalidation for user ${userId}.`)
        continue
      }
      const sessionDetailsKey = `${REDIS_KEY_PREFIX.SESSION_DETAILS}${sessionId}`
      const sessionDetails = await this.redisService.hgetall(sessionDetailsKey)

      if (sessionDetails && Object.keys(sessionDetails).length > 0) {
        // Blacklist Access Token if JTI exists
        if (sessionDetails.currentAccessTokenJti) {
          const accessTokenExp = parseInt(sessionDetails.accessTokenExp, 10)
          if (!isNaN(accessTokenExp)) {
            this.invalidateAccessTokenJti(sessionDetails.currentAccessTokenJti, accessTokenExp)
          }
        }
        // Blacklist Refresh Token if JTI exists
        if (sessionDetails.currentRefreshTokenJti) {
          this.markRefreshTokenJtiAsUsed(sessionDetails.currentRefreshTokenJti, sessionId)
        }

        pipeline.srem(userSessionsKey, sessionId) // Remove from user's set of sessions
        sessionKeysToDelete.push(sessionDetailsKey) // Mark session details for deletion

        if (sessionDetails.deviceId) {
          const deviceSessionKey = `${REDIS_KEY_PREFIX.DEVICE_SESSIONS}${sessionDetails.deviceId}`
          if (!deviceSessionUpdates.has(deviceSessionKey)) {
            deviceSessionUpdates.set(deviceSessionKey, [])
          }
          deviceSessionUpdates.get(deviceSessionKey)!.push(sessionId)
        }
        invalidatedCount++
        this.logger.verbose(`Session ${sessionId} for user ${userId} marked for bulk invalidation. Reason: ${reason}`)
      }
    }

    if (sessionKeysToDelete.length > 0) {
      pipeline.del(sessionKeysToDelete)
    }

    // Remove specific sessionIds from their respective DEVICE_SESSIONS sets
    deviceSessionUpdates.forEach((sessionsToRemove, deviceKey) => {
      if (sessionsToRemove.length > 0) {
        pipeline.srem(deviceKey, ...sessionsToRemove)
      }
    })

    await pipeline.exec()

    this.logger.log(`Invalidated ${invalidatedCount} sessions for user ${userId}. Reason: ${reason}`)
    return { invalidatedCount }
  }

  async invalidateSessionsByDeviceId(deviceId: number, reason: string = 'DEVICE_INVALIDATED'): Promise<number> {
    const deviceSessionsKey = `${REDIS_KEY_PREFIX.DEVICE_SESSIONS}${deviceId}`
    const sessionIds = await this.redisService.smembers(deviceSessionsKey)

    if (!sessionIds || sessionIds.length === 0) {
      this.logger.log(`No active sessions found for device ${deviceId} to invalidate.`)
      return 0
    }

    let invalidatedCount = 0
    const pipeline = this.redisService.client.pipeline()

    for (const sessionId of sessionIds) {
      const sessionDetails = await this.redisService.hgetall(`${REDIS_KEY_PREFIX.SESSION_DETAILS}${sessionId}`)
      if (sessionDetails && Object.keys(sessionDetails).length > 0) {
        if (sessionDetails.currentAccessTokenJti) {
          const accessTokenExp = parseInt(sessionDetails.accessTokenExp, 10)
          if (!isNaN(accessTokenExp)) {
            await this.invalidateAccessTokenJti(sessionDetails.currentAccessTokenJti, accessTokenExp) // Blacklist AT
          }
        }
        if (sessionDetails.currentRefreshTokenJti) {
          await this.markRefreshTokenJtiAsUsed(sessionDetails.currentRefreshTokenJti, sessionId) // Blacklist RT
        }
        pipeline.del(`${REDIS_KEY_PREFIX.SESSION_DETAILS}${sessionId}`)
        invalidatedCount++
        this.logger.verbose(`Session ${sessionId} for device ${deviceId} marked for invalidation. Reason: ${reason}`)

        // Remove session from user's set of sessions
        if (sessionDetails.userId) {
          pipeline.srem(`${REDIS_KEY_PREFIX.USER_SESSIONS}${sessionDetails.userId}`, sessionId)
        }
      }
    }

    // Remove the device's own set of sessions
    pipeline.del(deviceSessionsKey)

    await pipeline.exec()
    this.logger.log(`Invalidated ${invalidatedCount} sessions for device ${deviceId}. Reason: ${reason}`)
    return invalidatedCount
  }
}
