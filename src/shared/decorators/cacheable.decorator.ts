import { Logger } from '@nestjs/common'

export interface CacheableOptions {
  /**
   * Cache key identifier
   */
  key: string

  /**
   * Time-to-live in seconds (default: 300)
   */
  ttl?: number

  /**
   * Jitter TTL (giây) để tránh cache stampede. TTL cuối = ttl + random(0..ttlJitter)
   */
  ttlJitter?: number

  /**
   * Cache scope: 'global' or 'module' (default: 'global')
   */
  scope?: 'global' | 'module'

  /**
   * Module name (required when scope is 'module')
   */
  moduleName?: string

  /**
   * Enable JSON serialization (default: true)
   */
  serialize?: boolean

  /**
   * Stale-While-Revalidate window (giây). Nếu thiết lập, decorator sẽ lưu kèm
   * expiresAt và staleUntil để có thể trả dữ liệu cũ và tái tạo nền.
   */
  staleTtl?: number

  /**
   * Function to generate dynamic cache key based on method arguments
   */
  keyGenerator?: (...args: any[]) => string

  /**
   * Condition function to determine if result should be cached
   */
  condition?: (result: any) => boolean
}

export const REDIS_SERVICE_TOKEN = 'REDIS_SERVICE'

/**
 * Decorator để cache kết quả của method với Redis
 *
 * @example
 * ```typescript
 * @Cacheable({
 *   key: 'user:profile',
 *   ttl: 600,
 *   scope: 'module',
 *   moduleName: 'UserModule'
 * })
 * async getUserProfile(userId: string) {
 *   return await this.userRepository.findOne(userId)
 * }
 * ```
 */
export function Cacheable(options: CacheableOptions) {
  const logger = new Logger('CacheableDecorator')
  const inProgress = new Map<string, Promise<any>>()

  return function (target: any, propertyName: string, descriptor: PropertyDescriptor) {
    const method = descriptor.value

    descriptor.value = async function (...args: any[]) {
      const redisService = this.redisService || this.cacheService

      if (!redisService) {
        logger.warn(`RedisService not found in ${target.constructor.name}. Executing method without caching.`)
        return method.apply(this, args)
      }

      try {
        // Build cache key
        const cacheKey = buildCacheKey(options, args)

        // Try to get from cache first
        const cachedResult = await redisService.get(cacheKey)
        if (cachedResult !== null) {
          logger.debug(`Cache hit for key: ${cacheKey}`)
          // Hỗ trợ SWR nếu có staleTtl: dữ liệu cache được lưu dạng wrapper { value, expiresAt, staleUntil }
          if (
            options.staleTtl &&
            typeof cachedResult === 'object' &&
            cachedResult !== null &&
            'value' in cachedResult
          ) {
            const now = Date.now()
            const expiresAt = new Date(cachedResult.expiresAt).getTime()
            const staleUntil = new Date(cachedResult.staleUntil).getTime()
            if (now < expiresAt) {
              return cachedResult.value
            }
            if (now >= expiresAt && now < staleUntil) {
              if (!inProgress.has(cacheKey)) {
                // Soft lock phân tán: nếu lock đã tồn tại, không rebuild nền
                const lockKey = `rebuild:${cacheKey}`
                const gotLock = await redisService.tryAcquireLock(lockKey, 10)
                if (!gotLock) {
                  return cachedResult.value
                }
                const p = (async () => {
                  try {
                    const fresh = await method.apply(this, args)
                    const ttlBase = options.ttl || 300
                    const jitter = Math.floor(Math.random() * (options.ttlJitter || 0))
                    const wrapper = {
                      value: fresh,
                      expiresAt: new Date(Date.now() + ttlBase * 1000).toISOString(),
                      staleUntil: new Date(Date.now() + (ttlBase + (options.staleTtl || 0)) * 1000).toISOString()
                    }
                    await redisService.set(cacheKey, wrapper, ttlBase + (options.staleTtl || 0) + jitter)
                  } catch (e) {
                    logger.warn(`Background rebuild failed for key: ${cacheKey}`)
                  } finally {
                    await redisService.releaseLock(lockKey)
                    inProgress.delete(cacheKey)
                  }
                })()
                inProgress.set(cacheKey, p)
              }
              return cachedResult.value
            }
            // Hết luôn SWR window → rebuild đồng bộ
          } else {
            return options.serialize !== false ? cachedResult : JSON.parse(cachedResult)
          }
        }

        logger.debug(`Cache miss for key: ${cacheKey}`)

        // Execute original method
        const result = await method.apply(this, args)

        // Check condition before caching
        if (options.condition && !options.condition(result)) {
          logger.debug(`Condition not met for caching key: ${cacheKey}`)
          return result
        }

        // Cache the result
        const ttlBase = options.ttl || 300
        const jitter = Math.floor(Math.random() * (options.ttlJitter || 0))
        if (options.staleTtl) {
          const wrapper = {
            value: result,
            expiresAt: new Date(Date.now() + ttlBase * 1000).toISOString(),
            staleUntil: new Date(Date.now() + (ttlBase + options.staleTtl) * 1000).toISOString()
          }
          await redisService.set(cacheKey, wrapper, ttlBase + options.staleTtl + jitter)
        } else {
          const valueToCache = options.serialize !== false ? result : JSON.stringify(result)
          await redisService.set(cacheKey, valueToCache, ttlBase + jitter)
        }

        logger.debug(`Cached result for key: ${cacheKey}`)
        return result
      } catch (error) {
        logger.error(`Cache operation failed for ${target.constructor.name}.${propertyName}:`, error)
        // Fallback to original method execution
        return method.apply(this, args)
      }
    }

    return descriptor
  }
}

/**
 * Build cache key từ options và method arguments
 */
function buildCacheKey(options: CacheableOptions, args: any[]): string {
  let baseKey = options.key

  // Add scope prefix if specified
  if (options.scope === 'module' && options.moduleName) {
    baseKey = `${options.moduleName}:${baseKey}`
  }

  // Use custom key generator if provided
  if (options.keyGenerator) {
    const dynamicSuffix = options.keyGenerator(...args)
    return `${baseKey}:${dynamicSuffix}`
  }

  // Default: append serialized arguments as suffix
  if (args.length > 0) {
    const argsSuffix = args
      .map((arg) => {
        if (typeof arg === 'object') {
          return JSON.stringify(arg)
        }
        return String(arg)
      })
      .join(':')
    return `${baseKey}:${argsSuffix}`
  }

  return baseKey
}

/**
 * Cache invalidation decorator
 * Xóa cache keys theo pattern khi method được execute
 */
export function CacheEvict(pattern: string | string[]) {
  const logger = new Logger('CacheEvictDecorator')

  return function (target: any, propertyName: string, descriptor: PropertyDescriptor) {
    const method = descriptor.value

    descriptor.value = async function (...args: any[]) {
      const redisService = this.redisService || this.cacheService

      try {
        // Execute original method first
        const result = await method.apply(this, args)

        if (redisService) {
          const patterns = Array.isArray(pattern) ? pattern : [pattern]

          for (const pat of patterns) {
            await redisService.deleteByPattern(pat)
            logger.debug(`Evicted cache pattern: ${pat}`)
          }
        }

        return result
      } catch (error) {
        logger.error(`Cache eviction failed for ${target.constructor.name}.${propertyName}:`, error)
        // Still execute the method even if cache eviction fails
        return method.apply(this, args)
      }
    }

    return descriptor
  }
}

/**
 * Cache put decorator
 * Luôn execute method và cache kết quả (update cache)
 */
export function CachePut(options: CacheableOptions) {
  const logger = new Logger('CachePutDecorator')

  return function (target: any, propertyName: string, descriptor: PropertyDescriptor) {
    const method = descriptor.value

    descriptor.value = async function (...args: any[]) {
      const redisService = this.redisService || this.cacheService

      try {
        // Always execute original method
        const result = await method.apply(this, args)

        if (redisService) {
          const cacheKey = buildCacheKey(options, args)

          // Check condition before caching
          if (!options.condition || options.condition(result)) {
            const valueToCache = options.serialize !== false ? result : JSON.stringify(result)
            await redisService.set(cacheKey, valueToCache, options.ttl || 300)
            logger.debug(`Updated cache for key: ${cacheKey}`)
          }
        }

        return result
      } catch (error) {
        logger.error(`Cache put failed for ${target.constructor.name}.${propertyName}:`, error)
        return method.apply(this, args)
      }
    }

    return descriptor
  }
}
