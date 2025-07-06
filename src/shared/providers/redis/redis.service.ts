import { Inject, Injectable, Logger, OnModuleDestroy, OnModuleInit } from '@nestjs/common'
import Redis, { RedisKey, ChainableCommander } from 'ioredis'
import { IORedisKey } from './redis.constants'
import { IRedisService } from './redis.interface'

@Injectable()
export class RedisService implements IRedisService, OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(RedisService.name)

  constructor(@Inject(IORedisKey) public readonly client: Redis) {}

  onModuleInit() {
    this.logger.log('Redis client connected')
  }

  onModuleDestroy() {
    this.client.disconnect()
    this.logger.log('Redis client disconnected')
  }

  // --- Core Commands ---

  async set(key: RedisKey, value: any, ttlSeconds?: number): Promise<'OK' | null> {
    const serializedValue = JSON.stringify(value)
    if (ttlSeconds) {
      return this.client.set(key, serializedValue, 'EX', ttlSeconds)
    }
    return this.client.set(key, serializedValue)
  }

  async get<T>(key: RedisKey): Promise<T | null> {
    const value = await this.client.get(key)
    return value ? (JSON.parse(value) as T) : null
  }

  async del(keys: RedisKey | RedisKey[]): Promise<number> {
    const keysToDelete = Array.isArray(keys) ? keys : [keys]
    if (keysToDelete.length === 0) return 0
    return this.client.del(...keysToDelete)
  }

  // --- Hash Commands ---

  async hset(key: RedisKey, field: string, value: any): Promise<number> {
    return this.client.hset(key, field, JSON.stringify(value))
  }

  async hget<T>(key: RedisKey, field: string): Promise<T | null> {
    const value = await this.client.hget(key, field)
    return value ? (JSON.parse(value) as T) : null
  }

  async hgetall<T>(key: RedisKey): Promise<T | null> {
    const value = await this.client.hgetall(key)
    if (!value || Object.keys(value).length === 0) return null
    const deserialized = Object.entries(value).reduce(
      (acc, [key, val]) => {
        try {
          acc[key] = JSON.parse(val)
        } catch {
          acc[key] = val // Trả về chuỗi gốc nếu không parse được JSON
        }
        return acc
      },
      {} as Record<string, any>
    )
    return deserialized as T
  }

  async hdel(key: RedisKey, fields: string | string[]): Promise<number> {
    const fieldsToDelete = Array.isArray(fields) ? fields : [fields]
    return this.client.hdel(key, ...fieldsToDelete)
  }

  async hincrby(key: RedisKey, field: string, increment: number): Promise<number> {
    return this.client.hincrby(key, field, increment)
  }

  // --- Set Commands ---

  async sadd(key: RedisKey, members: readonly unknown[]): Promise<number> {
    const membersToAdd = members.map((m) => JSON.stringify(m))
    if (membersToAdd.length === 0) return 0
    return this.client.sadd(key, ...membersToAdd)
  }

  async srem(key: RedisKey, members: readonly unknown[]): Promise<number> {
    const membersToRemove = members.map((m) => JSON.stringify(m))
    if (membersToRemove.length === 0) return 0
    return this.client.srem(key, ...membersToRemove)
  }

  async sismember(key: RedisKey, member: unknown): Promise<boolean> {
    const result = await this.client.sismember(key, JSON.stringify(member))
    return result === 1
  }

  async smembers<T>(key: RedisKey): Promise<T[]> {
    const members = await this.client.smembers(key)
    return members.map((m) => {
      try {
        return JSON.parse(m) as T
      } catch {
        return m as any
      }
    })
  }

  // --- List Commands ---

  async lpush(key: RedisKey, elements: readonly unknown[]): Promise<number> {
    const elementsToPush = elements.map((el) => JSON.stringify(el))
    if (elementsToPush.length === 0) return 0
    return this.client.lpush(key, ...elementsToPush)
  }

  async lrange<T>(key: RedisKey, start: number, stop: number): Promise<T[]> {
    const elements = await this.client.lrange(key, start, stop)
    return elements.map((el) => {
      try {
        return JSON.parse(el) as T
      } catch {
        return el as any
      }
    })
  }

  // --- Utility Commands ---

  async exists(keys: RedisKey | RedisKey[]): Promise<number> {
    const keysToCheck = Array.isArray(keys) ? keys : [keys]
    if (keysToCheck.length === 0) return 0
    return this.client.exists(...keysToCheck)
  }

  async keys(pattern: string): Promise<string[]> {
    return this.client.keys(pattern)
  }

  pipeline(): ChainableCommander {
    return this.client.pipeline()
  }
}
