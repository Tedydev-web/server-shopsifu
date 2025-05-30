import { Module, Global, Provider, Logger } from '@nestjs/common'
import { CacheModule } from '@nestjs/cache-manager'
import { redisStore } from 'cache-manager-redis-yet'
import Redis, { RedisOptions } from 'ioredis'
import envConfig from 'src/shared/config'
import { IORedisKey } from './redis.constants'
import { RedisService } from './redis.service'

const redisClientFactory: Provider = {
  provide: IORedisKey,
  useFactory: () => {
    const logger = new Logger('RedisProvider')
    const redisOptions: RedisOptions = {
      host: envConfig.REDIS_HOST,
      port: envConfig.REDIS_PORT,
      password: envConfig.REDIS_PASSWORD || undefined, // Đảm bảo undefined nếu password rỗng
      db: envConfig.REDIS_DB,
      keyPrefix: envConfig.REDIS_KEY_PREFIX,
      lazyConnect: true,
      maxRetriesPerRequest: 3, // Giảm số lần thử lại để fail-fast hơn một chút
      connectTimeout: 10000, // 10 giây timeout
      retryStrategy: (times) => {
        const delay = Math.min(times * 100, 2000) // Tăng dần delay, max 2s
        logger.warn(`Redis connection failed. Retrying in ${delay}ms... (Attempt ${times})`)
        return delay
      },
      reconnectOnError: (err) => {
        logger.error(`Redis reconnectOnError: ${err.message}`)
        // Chỉ thử lại kết nối cho một số lỗi nhất định, ví dụ ECONNREFUSED
        const targetError = 'ECONNREFUSED'
        return err.message.includes(targetError)
      },
      enableOfflineQueue: true // Cho phép queue command khi offline
    }
    const client = new Redis(redisOptions)

    client.on('connect', () => {
      logger.log('Successfully connected to Redis.')
    })

    client.on('error', (error) => {
      logger.error('Redis client error:', error.message, error.stack)
    })

    client.on('reconnecting', () => {
      logger.warn('Redis client is reconnecting...')
    })

    client.on('end', () => {
      logger.warn('Redis client connection ended.')
    })

    return client
  }
}

@Global()
@Module({
  imports: [
    CacheModule.registerAsync({
      isGlobal: true,
      useFactory: async () => {
        const logger = new Logger('CacheManagerRedisStore')
        try {
          const store = await redisStore({
            socket: {
              host: envConfig.REDIS_HOST,
              port: envConfig.REDIS_PORT,
              connectTimeout: 10000
            },
            password: envConfig.REDIS_PASSWORD || undefined,
            database: envConfig.REDIS_DB,
            ttl: envConfig.REDIS_DEFAULT_TTL_MS,
            keyPrefix: envConfig.REDIS_KEY_PREFIX ? `${envConfig.REDIS_KEY_PREFIX}cache:` : 'cache:'
          })
          logger.log('CacheManager with Redis store configured successfully.')
          return {
            store: store
          }
        } catch (error) {
          logger.error('Failed to configure CacheManager with Redis store:', error)
          // Fallback to in-memory store or handle error as needed
          return {
            store: 'memory'
          }
        }
      }
    })
  ],
  providers: [redisClientFactory, RedisService],
  exports: [CacheModule, IORedisKey, RedisService]
})
export class RedisProviderModule {}
