import { Injectable, Inject, Logger, OnModuleDestroy, OnModuleInit, HttpStatus } from '@nestjs/common'
import Redis, { RedisKey, RedisValue } from 'ioredis'
import { ApiException } from 'src/shared/exceptions/api.exception'
import { IORedisKey } from './redis.constants'
import { CryptoService } from 'src/shared/services/crypto.service'

@Injectable()
export class RedisService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(RedisService.name)

  constructor(
    @Inject(IORedisKey) private readonly redisClient: Redis,
    private readonly cryptoService?: CryptoService
  ) {}

  async onModuleInit() {
    await this.redisClient.ping()
  }

  onModuleDestroy() {
    this.redisClient.disconnect()
  }

  get client(): Redis {
    return this.redisClient
  }

  // --- Core Redis Methods ---

  async set(
    key: RedisKey,
    value: RedisValue,
    mode?: string,
    duration?: number,
    condition?: string
  ): Promise<'OK' | null> {
    try {
      const args: any[] = []
      if (mode) {
        args.push(mode)
        if (duration !== undefined) {
          args.push(duration)
        }
      }
      if (condition) {
        args.push(condition)
      }

      return await this.redisClient.set(key, value, ...args)
    } catch (error) {
      throw error()
    }
  }

  async get(key: RedisKey): Promise<string | null> {
    try {
      return await this.redisClient.get(key)
    } catch (error) {
      throw error()
    }
  }

  async del(keys: RedisKey | RedisKey[]): Promise<number> {
    try {
      const keysToDelete = Array.isArray(keys) ? keys : [keys]
      if (keysToDelete.length === 0) return 0
      return await this.redisClient.del(keysToDelete)
    } catch (error) {
      throw error()
    }
  }

  async exists(keys: RedisKey | RedisKey[]): Promise<number> {
    try {
      const keysToCheck = Array.isArray(keys) ? keys : [keys]
      if (keysToCheck.length === 0) return 0
      return await this.redisClient.exists(keysToCheck)
    } catch (error) {
      throw error()
    }
  }

  async expire(key: RedisKey, seconds: number): Promise<number> {
    try {
      if (typeof seconds !== 'number' || isNaN(seconds) || !isFinite(seconds) || Math.floor(seconds) !== seconds) {
        throw new ApiException(HttpStatus.BAD_REQUEST, 'BadRequest', 'Error.Global.BadRequest')
      }
      return await this.redisClient.expire(key, seconds)
    } catch (error) {
      throw error()
    }
  }

  async ttl(key: RedisKey): Promise<number> {
    try {
      return await this.redisClient.ttl(key)
    } catch (error) {
      throw error()
    }
  }

  async incr(key: RedisKey): Promise<number> {
    return await this.redisClient.incr(key)
  }

  async decr(key: RedisKey): Promise<number> {
    return await this.redisClient.decr(key)
  }

  // --- Hash Commands ---

  async hset(key: RedisKey, field: string | Record<string, RedisValue>, value?: RedisValue): Promise<number> {
    try {
      if (typeof field === 'string' && value !== undefined) {
        return await this.redisClient.hset(key, field, value)
      }
      if (typeof field === 'object') {
        return await this.redisClient.hset(key, field)
      }
      throw new Error('Invalid arguments for hset')
    } catch (error) {
      throw error()
    }
  }

  async hget(key: RedisKey, field: string): Promise<string | null> {
    try {
      return await this.redisClient.hget(key, field)
    } catch (error) {
      throw error()
    }
  }

  async hmget(key: RedisKey, fields: string[]): Promise<(string | null)[]> {
    if (fields.length === 0) return []
    return await this.redisClient.hmget(key, ...fields)
  }

  async hgetall(key: RedisKey): Promise<Record<string, string>> {
    try {
      return await this.redisClient.hgetall(key)
    } catch (error) {
      throw error()
    }
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

  async lpop(key: RedisKey, count?: number): Promise<string | null | string[]> {
    if (count !== undefined) {
      return await this.redisClient.lpop(key, count)
    }
    return await this.redisClient.lpop(key)
  }

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

  // --- JSON Helpers ---

  async getJson<T>(key: RedisKey): Promise<T | null> {
    const jsonString = await this.get(key)
    if (!jsonString) return null
    try {
      return JSON.parse(jsonString) as T
    } catch {
      return null
    }
  }

  async setJson(key: RedisKey, value: any, ttlSeconds?: number): Promise<'OK' | null> {
    let jsonString: string
    try {
      jsonString = JSON.stringify(value)
    } catch {
      throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'ServerError', 'Error.Global.InternalServerError')
    }
    if (ttlSeconds !== undefined) {
      return this.set(key, jsonString, 'EX', ttlSeconds)
    } else {
      return this.set(key, jsonString)
    }
  }

  // --- Search & Keys ---

  async keys(pattern: string): Promise<string[]> {
    try {
      return await this.redisClient.keys(pattern)
    } catch (error) {
      throw error()
    }
  }

  async scan(cursor: number | string, ...args: any[]): Promise<[string, string[]]> {
    try {
      return await this.redisClient.scan(cursor, ...args)
    } catch (error) {
      throw error()
    }
  }

  async findKeys(pattern: string): Promise<string[]> {
    const foundKeys: string[] = []
    let cursor = '0'
    do {
      const [nextCursor, keys] = await this.scan(cursor, 'MATCH', pattern, 'COUNT', 100)
      keys.forEach((key) => foundKeys.push(key))
      cursor = nextCursor
    } while (cursor !== '0')
    return foundKeys
  }

  async deleteKeysByPattern(pattern: string): Promise<number> {
    const keysToDelete = await this.findKeys(pattern)
    if (keysToDelete.length > 0) {
      return await this.del(keysToDelete)
    }
    return 0
  }

  async pipeline(
    fn: (pipeline: ReturnType<Redis['pipeline']>) => ReturnType<Redis['pipeline']>
  ): Promise<[Error | null, any][] | null> {
    const pipeline = this.redisClient.pipeline()
    return await fn(pipeline).exec()
  }

  async publish(channel: string, message: string): Promise<number> {
    try {
      return await this.redisClient.publish(channel, message)
    } catch (error) {
      throw error()
    }
  }

  // --- Mã hóa dữ liệu ---

  async setEncrypted(key: RedisKey, value: string | object, ttlSeconds?: number): Promise<'OK' | null> {
    if (!this.cryptoService) {
      return this.setJson(key, value, ttlSeconds)
    }

    try {
      const encrypted = this.cryptoService.encrypt(value)
      if (ttlSeconds !== undefined) {
        return this.set(key, encrypted, 'EX', ttlSeconds)
      } else {
        return this.set(key, encrypted)
      }
    } catch (error) {
      throw error()
    }
  }

  async getDecrypted<T = any>(key: RedisKey, asObject: boolean = true): Promise<string | T | null> {
    if (!this.cryptoService) {
      return this.getJson<T>(key)
    }

    try {
      const encrypted = await this.get(key)
      if (!encrypted) return null

      return this.cryptoService.decrypt<T>(encrypted, asObject)
    } catch {
      return null
    }
  }

  async hsetEncrypted(
    key: RedisKey,
    fields: Record<string, string | number | boolean | object>,
    sensitiveFields?: string[]
  ): Promise<number> {
    const hashedFields: Record<string, string> = {}

    // Nếu CryptoService không khả dụng, lưu dữ liệu dưới dạng JSON
    if (!this.cryptoService) {
      for (const [field, value] of Object.entries(fields)) {
        hashedFields[field] = typeof value === 'object' ? JSON.stringify(value) : String(value)
      }
      return this.hset(key, hashedFields)
    }

    // Mã hóa các field nhạy cảm
    for (const [field, value] of Object.entries(fields)) {
      const shouldEncrypt = !sensitiveFields || sensitiveFields.includes(field)
      if (shouldEncrypt) {
        const valueToEncrypt = typeof value === 'string' ? value : JSON.stringify(value)
        hashedFields[field] = this.cryptoService.encrypt(valueToEncrypt)
      } else {
        hashedFields[field] = typeof value === 'object' ? JSON.stringify(value) : String(value)
      }
    }

    return this.hset(key, hashedFields)
  }

  async hgetDecrypted<T = any>(
    key: RedisKey,
    field: string,
    isSensitive: boolean = true,
    asObject: boolean = true
  ): Promise<string | T | null> {
    const value = await this.hget(key, field)
    if (!value) return null

    // Nếu không phải field nhạy cảm hoặc CryptoService không khả dụng
    if (!isSensitive || !this.cryptoService) {
      if (asObject) {
        try {
          return JSON.parse(value) as T
        } catch {
          return value as unknown as T
        }
      }
      return value
    }

    // Giải mã dữ liệu
    return this.cryptoService.decrypt<T>(value, asObject)
  }

  async hgetallDecrypted<T = Record<string, any>>(
    key: RedisKey,
    sensitiveFields?: string[]
  ): Promise<T | Record<string, string> | null>
  async hgetallDecrypted<T = Record<string, any>>(
    key: RedisKey,
    sensitiveFields: string[] | undefined,
    prefetchedData: Record<string, string>
  ): Promise<T | Record<string, string> | null>
  async hgetallDecrypted<T = Record<string, any>>(
    key: RedisKey,
    sensitiveFields?: string[],
    prefetchedData?: Record<string, string>
  ): Promise<T | Record<string, string> | null> {
    const data = prefetchedData || (await this.hgetall(key))
    if (!data || Object.keys(data).length === 0) return null

    // Nếu CryptoService không khả dụng, trả về dữ liệu gốc
    if (!this.cryptoService) {
      return data
    }

    const result: Record<string, any> = {}

    for (const [field, value] of Object.entries(data)) {
      const isSensitive = !sensitiveFields || sensitiveFields.includes(field)
      if (isSensitive) {
        try {
          result[field] = this.cryptoService.decrypt(value, true)
        } catch {
          result[field] = value
        }
      } else {
        try {
          result[field] = JSON.parse(value)
        } catch {
          result[field] = value
        }
      }
    }

    return result as T
  }

  async batchProcess(
    operations: Array<{
      command: string
      args: any[]
    }>
  ): Promise<any[]> {
    if (operations.length === 0) return []

    const pipeline = this.redisClient.pipeline()

    for (const op of operations) {
      if (typeof pipeline[op.command] === 'function') {
        pipeline[op.command](...op.args)
      }
    }

    const results = (await pipeline.exec()) || []

    // Trả về kết quả của mỗi hoạt động, bỏ qua lỗi
    return results.map(([err, result]) => {
      if (err) {
        return null
      }
      return result
    })
  }

  async mget(keys: RedisKey[]): Promise<(string | null)[]> {
    if (keys.length === 0) return []
    return this.redisClient.mget(keys)
  }

  async mset(keyValuePairs: Array<[RedisKey, RedisValue]>): Promise<'OK'> {
    if (keyValuePairs.length === 0) return 'OK'

    // Chuyển đổi mảng cặp thành mảng phẳng [key1, val1, key2, val2, ...]
    const args: (RedisKey | RedisValue)[] = []
    keyValuePairs.forEach(([key, value]) => {
      args.push(key, value)
    })

    return this.redisClient.mset(args)
  }

  async ltrim(key: RedisKey, start: number, stop: number): Promise<'OK'> {
    try {
      return await this.redisClient.ltrim(key, start, stop)
    } catch (error) {
      throw error()
    }
  }

  async exec(command: string, args: any[] = []): Promise<any> {
    try {
      return await this.redisClient.call(command, ...args)
    } catch (error) {
      throw error()
    }
  }
}
