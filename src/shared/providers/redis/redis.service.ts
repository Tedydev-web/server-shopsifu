import { Injectable, Inject, Logger, OnModuleDestroy, OnModuleInit } from '@nestjs/common'
import Redis, { RedisKey, RedisValue } from 'ioredis'
import { IORedisKey } from './redis.constants'
import envConfig from 'src/shared/config'

@Injectable()
export class RedisService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(RedisService.name)

  constructor(@Inject(IORedisKey) private readonly redisClient: Redis) {}

  async onModuleInit() {
    try {
      await this.redisClient.ping()
      this.logger.log('Successfully connected to Redis and ping was successful.')
    } catch (error) {
      this.logger.error('Failed to connect to Redis or ping was unsuccessful:', error)
      // Tuỳ theo chiến lược, có thể throw error để dừng app hoặc cho phép app chạy mà không có Redis
      // throw error;
    }
  }

  onModuleDestroy() {
    this.logger.log('Closing Redis connection...')
    void this.redisClient.quit()
  }

  get client(): Redis {
    return this.redisClient
  }

  // --- Generic Commands ---
  async get(key: RedisKey): Promise<string | null> {
    return await this.redisClient.get(key)
  }

  async set(key: RedisKey, value: RedisValue, ttlSeconds?: number): Promise<'OK'> {
    if (ttlSeconds) {
      return await this.redisClient.set(key, value, 'EX', ttlSeconds)
    }
    return await this.redisClient.set(key, value)
  }

  async del(keys: RedisKey | RedisKey[]): Promise<number> {
    const keysToDelete = Array.isArray(keys) ? keys : [keys]
    if (keysToDelete.length === 0) return 0
    return await this.redisClient.del(keysToDelete)
  }

  async exists(keys: RedisKey | RedisKey[]): Promise<number> {
    const keysToCheck = Array.isArray(keys) ? keys : [keys]
    if (keysToCheck.length === 0) return 0
    return await this.redisClient.exists(keysToCheck)
  }

  async expire(key: RedisKey, seconds: number): Promise<number> {
    return await this.redisClient.expire(key, seconds)
  }

  async ttl(key: RedisKey): Promise<number> {
    return await this.redisClient.ttl(key)
  }

  async incr(key: RedisKey): Promise<number> {
    return await this.redisClient.incr(key)
  }

  async decr(key: RedisKey): Promise<number> {
    return await this.redisClient.decr(key)
  }

  // --- Hash Commands ---
  async hget(key: RedisKey, field: string): Promise<string | null> {
    return await this.redisClient.hget(key, field)
  }

  async hset(key: RedisKey, field: string, value: RedisValue): Promise<number>
  async hset(key: RedisKey, data: Record<string, RedisValue>): Promise<number>
  async hset(key: RedisKey, fieldOrData: string | Record<string, RedisValue>, value?: RedisValue): Promise<number> {
    if (typeof fieldOrData === 'string' && value !== undefined) {
      return await this.redisClient.hset(key, fieldOrData, value)
    }
    if (typeof fieldOrData === 'object') {
      return await this.redisClient.hset(key, fieldOrData)
    }
    // Should not happen with TypeScript, but as a safeguard
    throw new Error('Invalid arguments for hset')
  }

  async hmget(key: RedisKey, fields: string[]): Promise<(string | null)[]> {
    if (fields.length === 0) return []
    return await this.redisClient.hmget(key, ...fields)
  }

  async hgetall(key: RedisKey): Promise<Record<string, string>> {
    return await this.redisClient.hgetall(key)
  }

  async hdel(key: RedisKey, fields: string | string[]): Promise<number> {
    const fieldsToDelete = Array.isArray(fields) ? fields : [fields]
    if (fieldsToDelete.length === 0) return 0
    return await this.redisClient.hdel(key, ...fieldsToDelete)
  }

  async hincrby(key: RedisKey, field: string, increment: number): Promise<number> {
    return await this.redisClient.hincrby(key, field, increment)
  }

  // --- Set Commands ---
  async sadd(key: RedisKey, members: RedisValue | RedisValue[]): Promise<number> {
    const membersToAdd = Array.isArray(members) ? members : [members]
    if (membersToAdd.length === 0) return 0
    return await this.redisClient.sadd(key, ...membersToAdd)
  }

  async srem(key: RedisKey, members: RedisValue | RedisValue[]): Promise<number> {
    const membersToRemove = Array.isArray(members) ? members : [members]
    if (membersToRemove.length === 0) return 0
    return await this.redisClient.srem(key, ...membersToRemove)
  }

  async smembers(key: RedisKey): Promise<string[]> {
    return await this.redisClient.smembers(key)
  }

  async sismember(key: RedisKey, member: RedisValue): Promise<number> {
    return await this.redisClient.sismember(key, member)
  }

  async scard(key: RedisKey): Promise<number> {
    return await this.redisClient.scard(key)
  }

  // --- List Commands ---
  async lpush(key: RedisKey, elements: RedisValue | RedisValue[]): Promise<number> {
    const elementsToPush = Array.isArray(elements) ? elements : [elements]
    if (elementsToPush.length === 0) return 0
    return await this.redisClient.lpush(key, ...elementsToPush)
  }

  async rpush(key: RedisKey, elements: RedisValue | RedisValue[]): Promise<number> {
    const elementsToPush = Array.isArray(elements) ? elements : [elements]
    if (elementsToPush.length === 0) return 0
    return await this.redisClient.rpush(key, ...elementsToPush)
  }

  async lpop(key: RedisKey): Promise<string | null>
  async lpop(key: RedisKey, count: number): Promise<string[]>
  async lpop(key: RedisKey, count?: number): Promise<string | null | string[]> {
    if (count !== undefined) {
      return await this.redisClient.lpop(key, count)
    }
    return await this.redisClient.lpop(key)
  }

  async rpop(key: RedisKey): Promise<string | null>
  async rpop(key: RedisKey, count: number): Promise<string[]>
  async rpop(key: RedisKey, count?: number): Promise<string | null | string[]> {
    if (count !== undefined) {
      return await this.redisClient.rpop(key, count)
    }
    return await this.redisClient.rpop(key)
  }

  async llen(key: RedisKey): Promise<number> {
    return await this.redisClient.llen(key)
  }

  async lrange(key: RedisKey, start: number, stop: number): Promise<string[]> {
    return await this.redisClient.lrange(key, start, stop)
  }

  // --- JSON specific (if using RedisJSON module, otherwise serialize/deserialize manually) ---
  // Assuming manual JSON stringification for now
  async getJson<T>(key: RedisKey): Promise<T | null> {
    const jsonString = await this.get(key)
    if (!jsonString) return null
    try {
      return JSON.parse(jsonString) as T
    } catch (error) {
      this.logger.error(`Failed to parse JSON for key ${String(key)}:`, error)
      return null
    }
  }

  async setJson(key: RedisKey, value: any, ttlSeconds?: number): Promise<'OK'> {
    try {
      const jsonString = JSON.stringify(value)
      return await this.set(key, jsonString, ttlSeconds)
    } catch (error) {
      this.logger.error(`Failed to stringify JSON for key ${String(key)}:`, error)
      throw new Error('Failed to stringify JSON for Redis')
    }
  }

  // --- Search/Scan ---
  async scan(cursor: number, pattern?: string, count?: number): Promise<[string, string[]]> {
    const args: (string | number)[] = [cursor]
    if (pattern) {
      args.push('MATCH', pattern)
    }
    if (count) {
      args.push('COUNT', count)
    }
    // ioredis typings for scan are a bit tricky, so casting to any temporarily
    const result = await (this.redisClient.scan as any)(...args)
    return [result[0].toString(), result[1]] // Ensure cursor is string
  }

  /**
   * Find all keys matching a pattern.
   * Warning: Use with caution on production with large datasets as SCAN can still block.
   * Consider using a more specific pattern or running in a background job.
   */
  async findKeys(pattern: string): Promise<string[]> {
    const foundKeys: string[] = []
    let cursor = 0
    do {
      const [nextCursor, keys] = await this.scan(cursor, pattern, 100)
      keys.forEach((key) => foundKeys.push(key))
      cursor = parseInt(nextCursor, 10)
    } while (cursor !== 0)
    return foundKeys
  }

  /**
   * Delete all keys matching a pattern.
   * Warning: Use with extreme caution on production.
   */
  async deleteKeysByPattern(pattern: string): Promise<number> {
    const keysToDelete = await this.findKeys(pattern)
    if (keysToDelete.length > 0) {
      return await this.del(keysToDelete)
    }
    return 0
  }

  /**
   * Executes a pipeline of commands.
   * Example:
   * const results = await redisService.pipeline(
   *   p => p.set('foo', 'bar').get('foo')
   * );
   * // results = [ [null, 'OK'], [null, 'bar'] ]
   */
  async pipeline(
    fn: (pipeline: ReturnType<Redis['pipeline']>) => ReturnType<Redis['pipeline']>
  ): Promise<[Error | null, any][] | null> {
    const pipeline = this.redisClient.pipeline()
    return await fn(pipeline).exec()
  }

  /**
   * Flushes the currently selected Redis database.
   * USE WITH EXTREME CAUTION, especially in production.
   * This is mainly for testing or specific reset scenarios.
   */
  async flushDb(): Promise<'OK'> {
    if (envConfig.NODE_ENV === 'production') {
      this.logger.warn('FLUSHDB command was called in production. This is highly discouraged. Aborting.')
      throw new Error('FLUSHDB is not allowed in production environment via RedisService.')
    }
    this.logger.warn(
      `Executing FLUSHDB on database ${this.redisClient.options.db}. This will delete all keys in the current DB.`
    )
    return await this.redisClient.flushdb()
  }
}
 