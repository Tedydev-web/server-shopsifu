import { Global, Module } from '@nestjs/common'
import { ConfigModule, ConfigService } from '@nestjs/config' // Added ConfigService
import { JwtModule } from '@nestjs/jwt'
import { Logger } from '@nestjs/common' // For logging in factory
import Redis from 'ioredis' // For Redis client instantiation

// Import services, repositories, guards
import { CookieService } from './services/cookie.service'
import { DeviceService } from './services/device.service'
import { EmailService } from './services/email.service'
import { GeolocationService } from './services/geolocation.service'
import { HashingService } from './services/hashing.service'
import { PrismaService } from './services/prisma.service'
import { SLTService } from './services/slt.service'
import { TokenService } from './services/token.service'
import { UserActivityService } from './services/user-activity.service'
import { UserAgentService } from './services/user-agent.service'
import { RedisService } from './services/redis.service'
import { CryptoService } from './services/crypto.service'

import { DeviceRepository } from '../routes/auth/repositories/device.repository'
import { RecoveryCodeRepository } from '../routes/auth/repositories/recovery-code.repository'
import { SessionRepository } from '../routes/auth/repositories/session.repository'
import { UserAuthRepository } from '../routes/auth/repositories/user-auth.repository'

import { ApiKeyGuard } from './guards/api-key.guard'
import { AuthenticationGuard } from './guards/authentication.guard'
import { BasicAuthGuard } from './guards/basic-auth.guard'
import { JwtAuthGuard } from './guards/jwt-auth.guard'
import { RolesGuard } from './guards/roles.guard'
import { ThrottlerProxyGuard } from './guards/throttler-proxy.guard'

// Import injection tokens
import {
  COOKIE_SERVICE,
  DEVICE_SERVICE,
  EMAIL_SERVICE,
  GEOLOCATION_SERVICE,
  HASHING_SERVICE,
  SLT_SERVICE,
  TOKEN_SERVICE,
  USER_AGENT_SERVICE
} from './constants/injection.tokens'
import { IORedisKey } from './constants/redis.constants' // Corrected path

const serviceClasses = [
  PrismaService,
  CookieService,
  DeviceService,
  EmailService,
  GeolocationService,
  HashingService,
  SLTService,
  TokenService,
  UserActivityService,
  UserAgentService,
  RedisService,
  CryptoService
]

const repositoryClasses = [DeviceRepository, RecoveryCodeRepository, SessionRepository, UserAuthRepository]

const guardClasses = [ApiKeyGuard, AuthenticationGuard, BasicAuthGuard, JwtAuthGuard, RolesGuard, ThrottlerProxyGuard]

// Providers for services injected via token
const tokenProviders = [
  { provide: COOKIE_SERVICE, useClass: CookieService },
  { provide: DEVICE_SERVICE, useClass: DeviceService },
  { provide: EMAIL_SERVICE, useClass: EmailService },
  { provide: GEOLOCATION_SERVICE, useClass: GeolocationService },
  { provide: HASHING_SERVICE, useClass: HashingService },
  { provide: SLT_SERVICE, useClass: SLTService },
  { provide: TOKEN_SERVICE, useClass: TokenService },
  { provide: USER_AGENT_SERVICE, useClass: UserAgentService }
]

// Define the provider for the Redis Client (IORedisKey)
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
      maxRetriesPerRequest: null, // Allow infinite retries for the client to connect on startup
      enableReadyCheck: false, // Do not wait for 'ready' state before resolving connection
      connectTimeout: 10000 // Timeout for connection attempts (10 seconds)
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
  inject: [ConfigService] // Inject ConfigService into the factory
}

const allProviders = [
  ...serviceClasses,
  ...repositoryClasses,
  ...guardClasses,
  ...tokenProviders,
  redisClientProvider // Add the Redis client provider
]
// Exports include all concrete classes and the token providers
const allExports = [...serviceClasses, ...repositoryClasses, ...guardClasses, ...tokenProviders, redisClientProvider] // Also export redisClientProvider if needed elsewhere by token

@Global()
@Module({
  imports: [ConfigModule, JwtModule],
  providers: allProviders,
  exports: allExports
})
export class SharedModule {}
