import { Injectable, Logger, OnModuleDestroy } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import Redis from 'ioredis'

export interface CacheConfig {
  ttl?: number
  prefix?: string
}

@Injectable()
export class RedisService implements OnModuleDestroy {
  private readonly logger = new Logger(RedisService.name)
  private readonly client: Redis
  private readonly defaultTtl: number = 300 // 5 minutes
  private readonly keyPrefix: string

  constructor(private readonly configService: ConfigService) {
    const redisUrl = this.configService.get<string>('redis.url') || 'redis://localhost:6379'
    this.keyPrefix = this.configService.get<string>('redis.keyPrefix') || 'shopsifu:'

    this.client = new Redis(redisUrl, {
      maxRetriesPerRequest: 3,
      lazyConnect: true,
      reconnectOnError: (err) => {
        const targetError = 'READONLY'
        return err.message.includes(targetError)
      }
    })

    this.client.on('connect', () => {
      this.logger.log('Redis connected successfully')
    })

    this.client.on('error', (error) => {
      this.logger.error('Redis connection error:', error)
    })

    this.client.on('close', () => {
      this.logger.warn('Redis connection closed')
    })
  }

  /**
   * Tạo cache key với prefix
   */
  private buildKey(key: string): string {
    return `${this.keyPrefix}${key}`
  }

  /**
   * Set giá trị vào cache
   */
  async set(key: string, value: any, ttl?: number): Promise<void> {
    try {
      const cacheKey = this.buildKey(key)
      const serializedValue = JSON.stringify(value)
      const cacheTtl = ttl || this.defaultTtl

      if (cacheTtl > 0) {
        await this.client.setex(cacheKey, cacheTtl, serializedValue)
      } else {
        await this.client.set(cacheKey, serializedValue)
      }

      this.logger.debug(`Cached key: ${cacheKey} with TTL: ${cacheTtl}s`)
    } catch (error) {
      this.logger.error(`Failed to set cache for key ${key}:`, error)
      // Không throw error để tránh break application
    }
  }

  /**
   * Lấy giá trị từ cache
   */
  async get<T = any>(key: string): Promise<T | null> {
    try {
      const cacheKey = this.buildKey(key)
      const cachedValue = await this.client.get(cacheKey)

      if (cachedValue === null) {
        this.logger.debug(`Cache miss for key: ${cacheKey}`)
        return null
      }

      this.logger.debug(`Cache hit for key: ${cacheKey}`)
      return JSON.parse(cachedValue) as T
    } catch (error) {
      this.logger.error(`Failed to get cache for key ${key}:`, error)
      return null
    }
  }

  /**
   * Xóa key khỏi cache
   */
  async del(key: string): Promise<boolean> {
    try {
      const cacheKey = this.buildKey(key)
      const result = await this.client.del(cacheKey)
      this.logger.debug(`Deleted cache key: ${cacheKey}`)
      return result > 0
    } catch (error) {
      this.logger.error(`Failed to delete cache for key ${key}:`, error)
      return false
    }
  }

  /**
   * Kiểm tra key có tồn tại không
   */
  async exists(key: string): Promise<boolean> {
    try {
      const cacheKey = this.buildKey(key)
      const result = await this.client.exists(cacheKey)
      return result === 1
    } catch (error) {
      this.logger.error(`Failed to check existence for key ${key}:`, error)
      return false
    }
  }

  /**
   * Lấy TTL của key
   */
  async ttl(key: string): Promise<number> {
    try {
      const cacheKey = this.buildKey(key)
      return await this.client.ttl(cacheKey)
    } catch (error) {
      this.logger.error(`Failed to get TTL for key ${key}:`, error)
      return -1
    }
  }

  /**
   * Set TTL cho key
   */
  async expire(key: string, ttl: number): Promise<boolean> {
    try {
      const cacheKey = this.buildKey(key)
      const result = await this.client.expire(cacheKey, ttl)
      return result === 1
    } catch (error) {
      this.logger.error(`Failed to set TTL for key ${key}:`, error)
      return false
    }
  }

  /**
   * Tìm keys theo pattern
   */
  async keys(pattern: string): Promise<string[]> {
    try {
      const searchPattern = this.buildKey(pattern)
      const keys = await this.client.keys(searchPattern)
      // Remove prefix from returned keys
      return keys.map((key) => key.replace(this.keyPrefix, ''))
    } catch (error) {
      this.logger.error(`Failed to get keys for pattern ${pattern}:`, error)
      return []
    }
  }

  /**
   * Xóa nhiều keys theo pattern
   */
  async deleteByPattern(pattern: string): Promise<number> {
    try {
      const keys = await this.keys(pattern)
      if (keys.length === 0) return 0

      const fullKeys = keys.map((key) => this.buildKey(key))
      const result = await this.client.del(...fullKeys)
      this.logger.debug(`Deleted ${result} keys matching pattern: ${pattern}`)
      return result
    } catch (error) {
      this.logger.error(`Failed to delete keys by pattern ${pattern}:`, error)
      return 0
    }
  }

  /**
   * Increment số
   */
  async increment(key: string, amount: number = 1): Promise<number> {
    try {
      const cacheKey = this.buildKey(key)
      return await this.client.incrby(cacheKey, amount)
    } catch (error) {
      this.logger.error(`Failed to increment key ${key}:`, error)
      return 0
    }
  }

  /**
   * Decrement số
   */
  async decrement(key: string, amount: number = 1): Promise<number> {
    try {
      const cacheKey = this.buildKey(key)
      return await this.client.decrby(cacheKey, amount)
    } catch (error) {
      this.logger.error(`Failed to decrement key ${key}:`, error)
      return 0
    }
  }

  /**
   * Thử acquire 1 lock đơn giản qua SET NX EX
   */
  async tryAcquireLock(lockKey: string, ttlSeconds: number = 10): Promise<boolean> {
    try {
      const key = this.buildKey(`lock:${lockKey}`)
      const res = await this.client.set(key, '1', 'EX', ttlSeconds, 'NX')
      return res === 'OK'
    } catch (error) {
      this.logger.error(`Failed to acquire lock ${lockKey}:`, error)
      return false
    }
  }

  /**
   * Giải phóng lock (best-effort)
   */
  async releaseLock(lockKey: string): Promise<void> {
    try {
      const key = this.buildKey(`lock:${lockKey}`)
      await this.client.del(key)
    } catch (error) {
      this.logger.warn(`Failed to release lock ${lockKey}: ${error?.message}`)
    }
  }

  /**
   * Flush all cache
   */
  async flushAll(): Promise<void> {
    try {
      await this.client.flushall()
      this.logger.log('Flushed all cache')
    } catch (error) {
      this.logger.error('Failed to flush cache:', error)
    }
  }

  /**
   * Lấy Redis client để sử dụng advanced operations
   */
  getClient(): Redis {
    return this.client
  }

  /**
   * Health check
   */
  async ping(): Promise<boolean> {
    try {
      const result = await this.client.ping()
      return result === 'PONG'
    } catch (error) {
      this.logger.error('Redis ping failed:', error)
      return false
    }
  }

  /**
   * Get cache statistics
   */
  async getStats(): Promise<any> {
    try {
      const info = await this.client.info('memory')
      const keyspace = await this.client.info('keyspace')

      return {
        memory: info,
        keyspace: keyspace,
        connected: this.client.status === 'ready'
      }
    } catch (error) {
      this.logger.error('Failed to get Redis stats:', error)
      return null
    }
  }

  /**
   * ♻️ Graceful Shutdown - Cleanup khi module bị destroy
   * Đảm bảo connections được đóng đúng cách
   */
  async onModuleDestroy() {
    try {
      this.logger.log('🔄 Initiating graceful Redis shutdown...')

      // Wait for pending operations to complete (max 5 seconds)
      const shutdownTimeout = 5000
      const startTime = Date.now()

      while (this.client.status === 'connecting' && Date.now() - startTime < shutdownTimeout) {
        await new Promise((resolve) => setTimeout(resolve, 100))
      }

      if (this.client.status !== 'end') {
        await this.client.quit()
        this.logger.log('✅ Redis connection closed gracefully')
      }
    } catch (error) {
      this.logger.error('❌ Error during Redis graceful shutdown:', error)

      // Force disconnect nếu graceful shutdown fails
      try {
        this.client.disconnect()
        this.logger.warn('⚠️ Redis connection force disconnected')
      } catch (forceError) {
        this.logger.error('❌ Failed to force disconnect Redis:', forceError)
      }
    }
  }

  /**
   * 🛡️ Advanced error handling với fallback strategies
   * Thử lại operation với backoff strategy
   */
  async withRetry<T>(operation: () => Promise<T>, maxRetries: number = 3, backoffMs: number = 1000): Promise<T | null> {
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        return await operation()
      } catch (error) {
        this.logger.warn(`Operation failed (attempt ${attempt}/${maxRetries}):`, error.message)

        if (attempt === maxRetries) {
          this.logger.error('Max retries reached, operation failed permanently')
          return null
        }

        // Exponential backoff
        const delay = backoffMs * Math.pow(2, attempt - 1)
        await new Promise((resolve) => setTimeout(resolve, delay))
      }
    }

    return null
  }

  /**
   * 📊 Health check với detailed status
   */
  async getHealthStatus(): Promise<{
    status: 'healthy' | 'unhealthy' | 'degraded'
    details: any
  }> {
    try {
      const startTime = Date.now()
      const pong = await this.client.ping()
      const responseTime = Date.now() - startTime

      const status = this.client.status
      const isHealthy = pong === 'PONG' && status === 'ready'

      return {
        status: isHealthy ? 'healthy' : responseTime > 1000 ? 'degraded' : 'unhealthy',
        details: {
          ping: pong,
          responseTime: `${responseTime}ms`,
          connectionStatus: status,
          connected: isHealthy,
          timestamp: new Date().toISOString()
        }
      }
    } catch (error) {
      return {
        status: 'unhealthy',
        details: {
          error: error.message,
          connectionStatus: this.client.status,
          connected: false,
          timestamp: new Date().toISOString()
        }
      }
    }
  }
}
