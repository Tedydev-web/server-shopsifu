import { Global, Module, forwardRef } from '@nestjs/common'
import { ConfigModule, ConfigService } from '@nestjs/config'
import { JwtModule } from '@nestjs/jwt'
import { Logger } from '@nestjs/common'
import { ClsModule } from 'nestjs-cls'
import Redis from 'ioredis'

import { CookieService } from './services/cookie.service'
import { EmailService } from './services/email.service'
import { GeolocationService } from './services/geolocation.service'
import { HashingService } from './services/hashing.service'
import { PrismaService } from './providers/prisma/prisma.service'
import { SLTService } from './services/slt.service'
import { TokenService } from './services/token.service'
import { UserAgentService } from './services/user-agent.service'
import { DeviceFingerprintService } from './services/device-fingerprint.service'
import { RedisService } from './providers/redis/redis.service'
import { CryptoService } from './services/crypto.service'
import { CaslAbilityFactory } from './providers/casl/casl-ability.factory'

import { ApiKeyGuard } from './guards/api-key.guard'
import { PermissionGuard } from './guards/permission.guard'

import {
  COOKIE_SERVICE,
  EMAIL_SERVICE,
  GEOLOCATION_SERVICE,
  HASHING_SERVICE,
  SLT_SERVICE,
  TOKEN_SERVICE,
  USER_AGENT_SERVICE,
  REDIS_SERVICE,
  DEVICE_FINGERPRINT_SERVICE
} from './constants/injection.tokens'
import { IORedisKey } from './providers/redis/redis.constants'
import { UserModule } from 'src/routes/user/user.module'

const serviceClasses = [
  PrismaService,
  CookieService,
  EmailService,
  GeolocationService,
  HashingService,
  SLTService,
  TokenService,
  UserAgentService,
  DeviceFingerprintService,
  RedisService,
  CryptoService,
  CaslAbilityFactory
]

const guardClasses = [ApiKeyGuard, PermissionGuard]

const tokenProviders = [
  { provide: COOKIE_SERVICE, useClass: CookieService },
  { provide: EMAIL_SERVICE, useClass: EmailService },
  { provide: GEOLOCATION_SERVICE, useClass: GeolocationService },
  { provide: HASHING_SERVICE, useClass: HashingService },
  { provide: SLT_SERVICE, useClass: SLTService },
  { provide: TOKEN_SERVICE, useClass: TokenService },
  { provide: USER_AGENT_SERVICE, useClass: UserAgentService },
  { provide: DEVICE_FINGERPRINT_SERVICE, useClass: DeviceFingerprintService },
  { provide: REDIS_SERVICE, useClass: RedisService }
]

const redisClientProvider = {
  provide: IORedisKey,
  useFactory: (configService: ConfigService) => {
    const logger = new Logger('RedisProviderFactory')
    const client = new Redis({
      host: configService.get<string>('REDIS_HOST', 'localhost'),
      port: configService.get<number>('REDIS_PORT', 6379),
      password: configService.get<string>('REDIS_PASSWORD'),
      db: configService.get<number>('REDIS_DB', 0),
      retryStrategy: (times: number) => {
        const delay = Math.min(times * 100, 3000) // Exponential backoff, max 3s
        logger.warn(`Redis: Retrying connection (attempt ${times}), next attempt in ${delay}ms.`)
        return delay
      },
      maxRetriesPerRequest: null,
      enableReadyCheck: false,
      connectTimeout: 10000
    })

    client.on('error', (err) => {
      logger.error('Redis Client Error:', err)
    })
    client.on('connect', () => {
      logger.log('Redis Client: Successfully connected.')
    })
    client.on('ready', () => {
      logger.log('Redis Client: Ready.')
    })

    return client
  },
  inject: [ConfigService]
}

const allProviders = [...serviceClasses, ...guardClasses, ...tokenProviders, redisClientProvider]
const allExports = [...serviceClasses, ...guardClasses, ...tokenProviders, redisClientProvider]

@Global()
@Module({
  imports: [
    ConfigModule,
    JwtModule,
    ClsModule.forRoot({
      global: true,
      middleware: { mount: true }
    }),
    forwardRef(() => UserModule)
  ],
  providers: allProviders,
  exports: allExports
})
export class SharedModule {}
