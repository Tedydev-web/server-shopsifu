import { Injectable, Logger } from '@nestjs/common'

@Injectable()
export class CacheService {
  private readonly logger = new Logger(CacheService.name)
  private cache = new Map<string, { data: any; expiry: number }>()

  async getOrSet<T>(
    key: string,
    fn: () => Promise<T>,
    ttlMs: number = 60000 // 1 phút mặc định
  ): Promise<T> {
    const now = Date.now()

    if (this.cache.has(key)) {
      const cached = this.cache.get(key)
      if (cached && cached.expiry > now) {
        this.logger.debug(`Cache hit for key: ${key}`)
        return cached.data as T
      }
      this.logger.debug(`Cache expired for key: ${key}`)
    }

    this.logger.debug(`Cache miss for key: ${key}`)
    const data = await fn()
    this.cache.set(key, { data, expiry: now + ttlMs })
    return data
  }

  invalidate(keyPattern: string): void {
    let count = 0
    for (const key of this.cache.keys()) {
      if (key.includes(keyPattern)) {
        this.cache.delete(key)
        count++
      }
    }
    this.logger.debug(`Invalidated ${count} cache entries with pattern: ${keyPattern}`)
  }

  invalidateAll(): void {
    const count = this.cache.size
    this.cache.clear()
    this.logger.debug(`Invalidated all ${count} cache entries`)
  }
}
