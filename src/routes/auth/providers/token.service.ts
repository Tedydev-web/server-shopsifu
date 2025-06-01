import { Injectable, Logger } from '@nestjs/common'
import { JwtService } from '@nestjs/jwt'
import envConfig from 'src/shared/config'
import {
  AccessTokenPayload,
  AccessTokenPayloadCreate,
  PendingLinkTokenPayload,
  PendingLinkTokenPayloadCreate
} from 'src/shared/types/jwt.type'
import { v4 as uuidv4 } from 'uuid'
import { Request, Response } from 'express'
import { Prisma } from '@prisma/client'
import { DeviceService } from './device.service'
import { PrismaTransactionClient } from 'src/shared/repositories/base.repository'
import { RedisService } from 'src/shared/providers/redis/redis.service'
import { REDIS_KEY_PREFIX } from 'src/shared/constants/redis.constants'
import ms from 'ms'
import {
  InvalidRefreshTokenException,
  RefreshTokenAlreadyUsedException,
  RefreshTokenNotFoundException,
  RefreshTokenSessionInvalidException,
  RefreshTokenDeviceMismatchException
} from 'src/routes/auth/auth.error'
import { ApiException } from 'src/shared/exceptions/api.exception'
import { HttpStatus } from '@nestjs/common'

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
    private readonly redisService: RedisService
  ) {}

  signAccessToken(payload: Omit<AccessTokenPayloadCreate, 'exp' | 'iat'>) {
    return this.jwtService.sign(payload, {
      secret: envConfig.ACCESS_TOKEN_SECRET,
      expiresIn: envConfig.ACCESS_TOKEN_EXPIRES_IN,
      algorithm: 'HS256'
    })
  }

  signShortLivedToken(payload: Omit<AccessTokenPayloadCreate, 'exp' | 'iat'>) {
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

  signPendingLinkToken(payload: PendingLinkTokenPayloadCreate): string {
    const jti = uuidv4()

    const secret = envConfig.PENDING_LINK_TOKEN_SECRET
    const expiresIn = envConfig.PENDING_LINK_TOKEN_EXPIRES_IN

    if (!secret || !expiresIn) {
      throw new ApiException(
        HttpStatus.INTERNAL_SERVER_ERROR,
        'SERVER_CONFIG_ERROR',
        'Error.Server.ConfigError.MissingTokenSecrets'
      )
    }

    return this.jwtService.sign(
      { ...payload, jti },
      {
        secret: secret,
        expiresIn: expiresIn,
        algorithm: 'HS256'
      }
    )
  }

  async verifyPendingLinkToken(token: string): Promise<PendingLinkTokenPayload> {
    const secret = envConfig.PENDING_LINK_TOKEN_SECRET
    if (!secret) {
      throw new ApiException(
        HttpStatus.INTERNAL_SERVER_ERROR,
        'SERVER_CONFIG_ERROR',
        'Error.Server.ConfigError.MissingTokenSecrets'
      )
    }

    try {
      const payload = await this.jwtService.verifyAsync<PendingLinkTokenPayload>(token, {
        secret: secret
      })
      return payload
    } catch (error) {
      throw InvalidRefreshTokenException
    }
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

    res.clearCookie(accessTokenConfig.name, {
      path: accessTokenConfig.path,
      domain: accessTokenConfig.domain,
      httpOnly: accessTokenConfig.httpOnly,
      secure: accessTokenConfig.secure,
      sameSite: accessTokenConfig.sameSite as 'lax' | 'strict' | 'none' | boolean
    })

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
      res.clearCookie(sltTokenConfig.name, {
        path: sltTokenConfig.path,
        domain: sltTokenConfig.domain,
        httpOnly: sltTokenConfig.httpOnly,
        secure: sltTokenConfig.secure,
        sameSite: sltTokenConfig.sameSite as 'lax' | 'strict' | 'none' | boolean
      })
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
    const { userId, deviceId, sessionId } = params

    const accessTokenJti = uuidv4()
    const refreshTokenJti = uuidv4()

    const accessTokenPayloadToSign: Omit<AccessTokenPayloadCreate, 'exp' | 'iat'> = {
      ...params,
      jti: accessTokenJti,
      isDeviceTrustedInSession: params.isDeviceTrustedInSession ?? false
    }

    const accessToken = this.signAccessToken(accessTokenPayloadToSign)

    const decodedAccessToken = this.jwtService.decode(accessToken)
    const accessTokenExp = decodedAccessToken.exp

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

    const result = await this.redisService.set(usedKey, sessionId, 'EX', effectiveTtl, 'NX')

    if (result === null) {
      return false
    }
    return true
  }

  async invalidateRefreshTokenJti(refreshTokenJti: string, sessionId: string) {
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
    const nowInSeconds = Math.floor(Date.now() / 1000)
    const ttl = accessTokenExp - nowInSeconds
    if (ttl > 0) {
      await this.redisService.set(`${REDIS_KEY_PREFIX.ACCESS_TOKEN_BLACKLIST}${accessTokenJti}`, 'revoked', 'EX', ttl)
    }
  }

  async findSessionIdByRefreshTokenJti(refreshTokenJti: string): Promise<string | null> {
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
    const auditLogDetails: Prisma.JsonObject = {
      refreshTokenJtiProvided: clientRefreshTokenJti,
      userAgent,
      ip
    }

    if (await this.isRefreshTokenJtiBlacklisted(clientRefreshTokenJti)) {
      auditLogDetails.reason = 'REFRESH_TOKEN_JTI_BLACKLISTED'

      throw InvalidRefreshTokenException
    }

    const sessionId = await this.findSessionIdByRefreshTokenJti(clientRefreshTokenJti)
    if (!sessionId) {
      auditLogDetails.reason = 'SESSION_NOT_FOUND_FOR_RT_JTI'

      throw RefreshTokenNotFoundException
    }
    auditLogDetails.sessionId = sessionId

    const sessionKey = `${REDIS_KEY_PREFIX.SESSION_DETAILS}${sessionId}`
    const sessionDetails = await this.redisService.hgetall(sessionKey)

    if (!sessionDetails || Object.keys(sessionDetails).length === 0) {
      await this.invalidateRefreshTokenJti(clientRefreshTokenJti, sessionId)
      auditLogDetails.reason = 'SESSION_EMPTY_OR_NOT_FOUND_IN_REDIS'

      throw RefreshTokenSessionInvalidException
    }
    auditLogDetails.sessionUserId = parseInt(sessionDetails.userId, 10)
    auditLogDetails.sessionDeviceId = parseInt(sessionDetails.deviceId, 10)

    if (sessionDetails.currentRefreshTokenJti !== clientRefreshTokenJti) {
      await this.invalidateSession(sessionId, 'SUSPECTED_TOKEN_THEFT_ON_REFRESH')
      auditLogDetails.reason = 'REFRESH_TOKEN_JTI_MISMATCH'
      auditLogDetails.suspectedCurrentSessionRtJti = sessionDetails.currentRefreshTokenJti

      throw InvalidRefreshTokenException
    }

    const expectedUserAgentFingerprint = this.deviceService.basicDeviceFingerprint(sessionDetails.userAgent)
    const currentUserAgentFingerprint = this.deviceService.basicDeviceFingerprint(userAgent)
    if (expectedUserAgentFingerprint !== currentUserAgentFingerprint) {
      auditLogDetails.reason = 'USER_AGENT_MISMATCH'
      auditLogDetails.expectedUserAgentFingerprint = expectedUserAgentFingerprint
      auditLogDetails.currentUserAgentFingerprint = currentUserAgentFingerprint

      throw RefreshTokenDeviceMismatchException
    }

    const now = new Date()
    await this.redisService.hset(sessionKey, 'lastActiveAt', now.toISOString())

    const isDeviceTrustedInSessionBoolean = sessionDetails.isTrusted === 'true'

    const newAccessTokenJti = uuidv4()
    const accessTokenPayloadToSign: Omit<AccessTokenPayloadCreate, 'exp' | 'iat'> = {
      userId: Number(sessionDetails.userId),
      deviceId: Number(sessionDetails.deviceId),
      roleId: Number(sessionDetails.roleId),
      roleName: sessionDetails.roleName,
      sessionId: sessionId,
      isDeviceTrustedInSession: isDeviceTrustedInSessionBoolean,
      jti: newAccessTokenJti
    }

    const newAccessToken = this.signAccessToken(accessTokenPayloadToSign)

    const finalAccessTokenPayload: AccessTokenPayload = {
      ...accessTokenPayloadToSign,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + Math.floor(ms(envConfig.ACCESS_TOKEN_EXPIRES_IN) / 1000),

      isDeviceTrustedInSession: accessTokenPayloadToSign.isDeviceTrustedInSession ?? false
    }

    await this.redisService.hset(sessionKey, 'currentAccessTokenJti', newAccessTokenJti)

    const shouldRotateRefreshToken = true
    let newRefreshTokenJti: string | undefined = undefined
    let maxAgeForCookie: number | undefined = undefined

    if (shouldRotateRefreshToken) {
      const oldRtKey = `${REDIS_KEY_PREFIX.REFRESH_TOKEN_JTI_TO_SESSION}${clientRefreshTokenJti}`
      const oldRtTtl = await this.redisService.ttl(oldRtKey)
      const blacklistTtl = oldRtTtl > 0 ? oldRtTtl : 300
      const markedSuccessfully = await this.markRefreshTokenJtiAsUsed(clientRefreshTokenJti, sessionId, blacklistTtl)

      if (!markedSuccessfully) {
        await this.invalidateSession(sessionId, 'RT_JTI_ALREADY_USED_ON_REFRESH_ATTEMPT')
        throw RefreshTokenAlreadyUsedException
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
      auditLogDetails.rotatedToNewRefreshTokenJti = newRefreshTokenJti
    } else {
      newRefreshTokenJti = clientRefreshTokenJti
      maxAgeForCookie =
        parseInt(sessionDetails.maxAgeForRefreshTokenCookie, 10) || envConfig.REFRESH_TOKEN_COOKIE_MAX_AGE
    }

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
  }

  async invalidateSession(sessionId: string, reason: string = 'UNKNOWN') {
    const pipeline = this.redisService.client.pipeline()
    await this._addSessionInvalidationToPipeline(pipeline, sessionId, reason)
    const results = await pipeline.exec()
    if (results) {
      results.forEach(([err, result], index) => {})
    }
  }

  async invalidateAllUserSessions(
    userId: number,
    reason: string = 'UNKNOWN_BULK_INVALIDATION',
    sessionIdToExclude?: string
  ): Promise<{ invalidatedCount: number }> {
    const userSessionsKey = `${REDIS_KEY_PREFIX.USER_SESSIONS}${userId}`
    const sessionIds = await this.redisService.smembers(userSessionsKey)

    if (!sessionIds || sessionIds.length === 0) {
      return { invalidatedCount: 0 }
    }

    let invalidatedCount = 0
    const pipeline = this.redisService.client.pipeline()
    const sessionKeysToDelete: string[] = []
    const deviceSessionUpdates: Map<string, string[]> = new Map()

    for (const sessionId of sessionIds) {
      if (sessionId === sessionIdToExclude) {
        continue
      }
      const sessionDetailsKey = `${REDIS_KEY_PREFIX.SESSION_DETAILS}${sessionId}`
      const sessionDetails = await this.redisService.hgetall(sessionDetailsKey)

      if (sessionDetails && Object.keys(sessionDetails).length > 0) {
        if (sessionDetails.currentAccessTokenJti) {
          const accessTokenExp = parseInt(sessionDetails.accessTokenExp, 10)
          if (!isNaN(accessTokenExp)) {
            this.invalidateAccessTokenJti(sessionDetails.currentAccessTokenJti, accessTokenExp)
          }
        }

        if (sessionDetails.currentRefreshTokenJti) {
          this.markRefreshTokenJtiAsUsed(sessionDetails.currentRefreshTokenJti, sessionId)
        }

        pipeline.srem(userSessionsKey, sessionId)
        sessionKeysToDelete.push(sessionDetailsKey)

        if (sessionDetails.deviceId) {
          const deviceSessionKey = `${REDIS_KEY_PREFIX.DEVICE_SESSIONS}${sessionDetails.deviceId}`
          if (!deviceSessionUpdates.has(deviceSessionKey)) {
            deviceSessionUpdates.set(deviceSessionKey, [])
          }
          deviceSessionUpdates.get(deviceSessionKey)!.push(sessionId)
        }
        invalidatedCount++
      }
    }

    if (sessionKeysToDelete.length > 0) {
      pipeline.del(sessionKeysToDelete)
    }

    deviceSessionUpdates.forEach((sessionsToRemove, deviceKey) => {
      if (sessionsToRemove.length > 0) {
        pipeline.srem(deviceKey, ...sessionsToRemove)
      }
    })

    await pipeline.exec()

    return { invalidatedCount }
  }

  async invalidateSessionsByDeviceId(deviceId: number, reason: string = 'DEVICE_INVALIDATED'): Promise<number> {
    const deviceSessionsKey = `${REDIS_KEY_PREFIX.DEVICE_SESSIONS}${deviceId}`
    const sessionIds = await this.redisService.smembers(deviceSessionsKey)

    if (!sessionIds || sessionIds.length === 0) {
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
            await this.invalidateAccessTokenJti(sessionDetails.currentAccessTokenJti, accessTokenExp)
          }
        }
        if (sessionDetails.currentRefreshTokenJti) {
          await this.markRefreshTokenJtiAsUsed(sessionDetails.currentRefreshTokenJti, sessionId)
        }
        pipeline.del(`${REDIS_KEY_PREFIX.SESSION_DETAILS}${sessionId}`)
        invalidatedCount++

        if (sessionDetails.userId) {
          pipeline.srem(`${REDIS_KEY_PREFIX.USER_SESSIONS}${sessionDetails.userId}`, sessionId)
        }
      }
    }

    pipeline.del(deviceSessionsKey)

    await pipeline.exec()
    return invalidatedCount
  }
}
