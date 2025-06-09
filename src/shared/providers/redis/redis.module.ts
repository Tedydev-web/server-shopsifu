import { DynamicModule, Global, Logger, Module, Provider } from '@nestjs/common'
import { CacheModule } from '@nestjs/cache-manager'
import { redisStore } from 'cache-manager-redis-yet'
import Redis, { RedisOptions } from 'ioredis'

import { IORedisKey } from './redis.constants'
import { RedisService } from './redis.service'
import { ConfigService, ConfigModule } from '@nestjs/config'
import { CryptoService } from 'src/shared/services/crypto.service'

export interface RedisModuleOptions {
  connectionOptions: RedisOptions
  onClientReady?: (client: Redis) => void
}

export interface RedisAsyncModuleOptions {
  useFactory: (...args: any[]) => Promise<RedisModuleOptions> | RedisModuleOptions
  inject?: any[]
}

// Redis client factory
const createRedisClient = (): Provider => ({
  provide: IORedisKey,
  useFactory: (configService: ConfigService) => {
    // Tạo và trả về Redis client instance
    const redisClient = new Redis({
      host: configService.get('REDIS_HOST', 'localhost'),
      port: configService.get('REDIS_PORT', 6379),
      password: configService.get('REDIS_PASSWORD', ''),
      db: configService.get('REDIS_DB', 0)
    })
    return redisClient
  },
  inject: [ConfigService]
})

// Redis service factory
const createRedisService = (): Provider => ({
  provide: RedisService,
  useClass: RedisService
})

@Global()
@Module({
  imports: [
    CacheModule.registerAsync({
      isGlobal: true,
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: async (configService: ConfigService) => {
        const logger = new Logger('CacheManagerRedisStore')
        try {
          const store = await redisStore({
            socket: {
              host: configService.get<string>('REDIS_HOST'),
              port: configService.get<number>('REDIS_PORT'),
              connectTimeout: 10000
            },
            password: configService.get<string>('REDIS_PASSWORD') || undefined,
            database: configService.get<number>('REDIS_DB'),
            ttl: configService.get<number>('REDIS_DEFAULT_TTL_MS'),
            keyPrefix: configService.get<string>('REDIS_KEY_PREFIX')
              ? `${configService.get<string>('REDIS_KEY_PREFIX')}cache:`
              : 'cache:'
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
  providers: [createRedisClient(), createRedisService(), RedisService, CryptoService],
  exports: [IORedisKey, RedisService]
})
export class RedisProviderModule {
  static register(options: RedisModuleOptions): DynamicModule {
    return {
      module: RedisProviderModule,
      providers: [
        createRedisClient(),
        {
          provide: 'REDIS_MODULE_OPTIONS',
          useValue: options
        }
      ],
      exports: [IORedisKey]
    }
  }

  static registerAsync(options: RedisAsyncModuleOptions): DynamicModule {
    return {
      module: RedisProviderModule,
      imports: options.inject ? [] : [],
      providers: [
        createRedisClient(),
        {
          provide: 'REDIS_MODULE_OPTIONS',
          useFactory: options.useFactory,
          inject: options.inject || []
        }
      ],
      exports: [IORedisKey]
    }
  }
}
