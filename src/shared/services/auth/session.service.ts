import { Injectable, Logger } from '@nestjs/common'
import { Session } from '@prisma/client'
import envConfig from 'src/shared/config'
import { RedisKeyManager } from '../../providers/redis/redis-key.manager'
import { RedisService } from '../../providers/redis/redis.service'
import ms from 'ms'

@Injectable()
export class SessionService {
  private readonly logger = new Logger(SessionService.name)
  private readonly sessionTtlSeconds: number

  constructor(private readonly redis: RedisService) {
    // Cache TTL cho session bằng với thời gian hết hạn của Refresh Token
    this.sessionTtlSeconds = ms(envConfig.REFRESH_TOKEN_EXPIRES_IN) / 1000
  }

  // === Session Lifecycle Management ===

  async createSession(session: Session): Promise<void> {
    const sessionKey = RedisKeyManager.getSessionKey(session.id)
    const userSessionsKey = RedisKeyManager.getUserSessionsKey(session.userId)
    try {
      const pipeline = this.redis.pipeline()
      pipeline.set(sessionKey, JSON.stringify(session), 'EX', this.sessionTtlSeconds)
      pipeline.sadd(userSessionsKey, session.id)
      await pipeline.exec()
    } catch (error) {
      this.logger.error(`Failed to create session in Redis for user ${session.userId}`, error)
      // Không re-throw lỗi để không làm gián đoạn luồng chính, nhưng cần log lại
    }
  }

  async getSession(sessionId: string): Promise<Session | null> {
    const key = RedisKeyManager.getSessionKey(sessionId)
    return this.redis.get<Session>(key)
  }

  async getUserSessions(userId: number): Promise<string[]> {
    const key = RedisKeyManager.getUserSessionsKey(userId)
    return this.redis.smembers<string>(key)
  }

  async revokeSession(userId: number, sessionId: string): Promise<void> {
    const sessionKey = RedisKeyManager.getSessionKey(sessionId)
    const userSessionsKey = RedisKeyManager.getUserSessionsKey(userId)
    try {
      const pipeline = this.redis.pipeline()
      pipeline.del(sessionKey)
      pipeline.srem(userSessionsKey, sessionId)
      await pipeline.exec()
    } catch (error) {
      this.logger.error(`Failed to revoke session ${sessionId} in Redis for user ${userId}`, error)
    }
  }

  async revokeAllUserSessions(userId: number): Promise<void> {
    const userSessionsKey = RedisKeyManager.getUserSessionsKey(userId)
    try {
      const sessionIds = await this.redis.smembers<string>(userSessionsKey)
      if (sessionIds.length > 0) {
        const sessionKeys = sessionIds.map((id) => RedisKeyManager.getSessionKey(id))
        const pipeline = this.redis.pipeline()
        pipeline.del([...sessionKeys, userSessionsKey])
        await pipeline.exec()
      }
    } catch (error) {
      this.logger.error(`Failed to revoke all sessions in Redis for user ${userId}`, error)
    }
  }

  // === Refresh Token Rotation Helpers ===

  async markRefreshTokenAsUsed(jti: string): Promise<void> {
    const key = RedisKeyManager.getUsedRefreshTokenKey(jti)
    await this.redis.set(key, '1', this.sessionTtlSeconds)
  }

  async isRefreshTokenUsed(jti: string): Promise<boolean> {
    const key = RedisKeyManager.getUsedRefreshTokenKey(jti)
    const result = await this.redis.get(key)
    return result === '1'
  }

  // === Token Blacklist Management ===

  async addToBlacklist(jti: string, ttlSeconds: number): Promise<void> {
    if (ttlSeconds > 0) {
      const key = RedisKeyManager.getBlacklistedTokenKey(jti)
      await this.redis.set(key, '1', Math.ceil(ttlSeconds))
    }
  }

  async isBlacklisted(jti: string): Promise<boolean> {
    const key = RedisKeyManager.getBlacklistedTokenKey(jti)
    const result = await this.redis.get(key)
    return result === '1'
  }
}
