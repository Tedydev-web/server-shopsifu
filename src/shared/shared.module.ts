import { Global, Module } from '@nestjs/common'
import { PrismaService } from 'src/shared/services/prisma.service'
import { HashingService } from './services/hashing.service'
import { TokenService } from './services/token.service'
import { JwtModule } from '@nestjs/jwt'
import { AccessTokenGuard } from 'src/shared/guards/access-token.guard'
import { APIKeyGuard } from 'src/shared/guards/api-key.guard'
import { PermissionGuard } from 'src/shared/guards/permission.guard'
import { APP_GUARD } from '@nestjs/core'
import { AuthenticationGuard } from 'src/shared/guards/authentication.guard'
import { SharedUserRepository } from 'src/shared/repositories/shared-user.repo'
import { EmailService } from 'src/shared/services/email.service'
import { TwoFactorService } from 'src/shared/services/2fa.service'
import { CookieService } from './services/cookie.service'
import { ConfigModule, ConfigService } from '@nestjs/config'
import { RedisService } from './providers/redis/redis.service'
import { IORedisKey } from './providers/redis/redis.constants'
import Redis from 'ioredis'
import { Logger } from '@nestjs/common'
import { CryptoService } from './services/crypto.service'
import { UserAgentService } from './services/user-agent.service'
import { SecurityHeadersMiddleware } from './middleware/security-headers.middleware'
import { CsrfProtectionMiddleware } from './middleware/csrf.middleware'
import { EnvConfigType } from './config'
import { GeolocationService } from './services/geolocation.service'
import { DeviceFingerprintService } from './services/device-fingerprint.service'
import { SessionService } from './services/session.service'
import { SltService } from './services/slt.service'

const redisClientProvider = {
  provide: IORedisKey,
  useFactory: (configService: ConfigService<EnvConfigType>) => {
    const logger = new Logger('RedisProviderFactory')
    const redisConfig = configService.get('redis')
    const client = new Redis({
      host: redisConfig.host,
      port: redisConfig.port,
      password: redisConfig.password,
      db: redisConfig.db,
      retryStrategy: (times: number) => {
        const delay = Math.min(times * 100, 3000) // Tối đa 3s
        logger.warn(`Redis: Đang thử kết nối lại (lần ${times}), thử lại sau ${delay}ms.`)
        return delay
      },
    })

    client.on('error', (err) => {
      logger.error('Redis Client Error:', err)
    })

    return client
  },
  inject: [ConfigService],
}

const sharedServices = [
  PrismaService,
  HashingService,
  TokenService,
  EmailService,
  SharedUserRepository,
  TwoFactorService,
  CookieService,
  CryptoService,
  UserAgentService,
  RedisService,
  GeolocationService,
  DeviceFingerprintService,
  SessionService,
  SltService,
]

const sharedMiddlewares = [CsrfProtectionMiddleware, SecurityHeadersMiddleware]

const sharedGuards = [AccessTokenGuard, APIKeyGuard, AuthenticationGuard, PermissionGuard]

const allProviders = [
  ...sharedServices,
  ...sharedMiddlewares,
  ...sharedGuards,
  redisClientProvider,
  {
    provide: APP_GUARD,
    useClass: AuthenticationGuard,
  },
  {
    provide: APP_GUARD,
    useClass: PermissionGuard,
  },
]

@Global()
@Module({
  imports: [JwtModule, ConfigModule],
  providers: allProviders,
  exports: [...sharedServices, ...sharedMiddlewares, ...sharedGuards],
})
export class SharedModule {}
