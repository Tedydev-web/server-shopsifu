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
          return options.serialize !== false ? cachedResult : JSON.parse(cachedResult)
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
        const valueToCache = options.serialize !== false ? result : JSON.stringify(result)
        await redisService.set(cacheKey, valueToCache, options.ttl || 300)

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
