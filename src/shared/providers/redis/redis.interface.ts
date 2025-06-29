import { Redis, ChainableCommander } from 'ioredis'

export interface IRedisService {
  readonly client: Redis

  set(key: string, value: any, ttlSeconds?: number): Promise<'OK' | null>
  get<T>(key: string): Promise<T | null>
  del(keys: string | string[]): Promise<number>

  hset(key: string, field: string, value: any): Promise<number>
  hget<T>(key: string, field: string): Promise<T | null>
  hgetall<T>(key: string): Promise<T | null>
  hdel(key: string, fields: string | string[]): Promise<number>
  hincrby(key: string, field: string, increment: number): Promise<number>

  sadd(key: string, members: readonly unknown[]): Promise<number>
  srem(key: string, members: readonly unknown[]): Promise<number>
  sismember(key: string, member: unknown): Promise<boolean>
  smembers<T>(key: string): Promise<T[]>

  lpush(key: string, elements: readonly unknown[]): Promise<number>
  lrange<T>(key: string, start: number, stop: number): Promise<T[]>

  exists(keys: string | string[]): Promise<number>
  keys(pattern: string): Promise<string[]>

  pipeline(): ChainableCommander
}
