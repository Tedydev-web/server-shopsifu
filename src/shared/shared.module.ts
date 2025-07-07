import { Global, Module } from '@nestjs/common'
import { PrismaService } from 'src/shared/services/prisma.service'
import { HashingService } from './services/hashing.service'
import { TokenService } from './services/auth/token.service'
import { JwtModule } from '@nestjs/jwt'
import { AccessTokenGuard } from 'src/shared/guards/access-token.guard'
import { PaymentAPIKeyGuard } from 'src/shared/guards/payment-api-key.guard'
import { APP_GUARD } from '@nestjs/core'
import { AuthenticationGuard } from 'src/shared/guards/authentication.guard'
import { SharedUserRepository } from 'src/shared/repositories/shared-user.repo'
import { EmailService } from 'src/shared/services/email.service'
import { TwoFactorService } from 'src/shared/services/auth/2fa.service'
import { CookieService } from './services/cookie.service'
import { RedisService } from './providers/redis/redis.service'
import { IORedisKey } from './providers/redis/redis.constants'
import Redis from 'ioredis'
import { Logger } from '@nestjs/common'
import { CryptoService } from './services/crypto.service'
import { UserAgentService } from './services/auth/user-agent.service'
import { SecurityHeadersMiddleware } from './middleware/security-headers.middleware'
import { CsrfProtectionMiddleware } from './middleware/csrf.middleware'
import envConfig from './config'
import { GeolocationService } from './services/auth/geolocation.service'
import { DeviceFingerprintService } from './services/auth/device-fingerprint.service'
import { SessionService } from './services/auth/session.service'
import { SltService } from './services/slt.service'
import { PaginationService } from './services/pagination.service'
import { SharedRoleRepository } from './repositories/shared-role.repo'
import { S3Service } from './services/s3.service'

const redisClientProvider = {
  provide: IORedisKey,
  useFactory: () => {
    const logger = new Logger('RedisProviderFactory')
    const redisConfig = envConfig.REDIS_HOST
    const client = new Redis({
      host: envConfig.REDIS_HOST,
      port: envConfig.REDIS_PORT,
      password: envConfig.REDIS_PASSWORD,
      db: envConfig.REDIS_DB,
      retryStrategy: (times: number) => {
        const delay = Math.min(times * 100, 3000) // Tối đa 3s
        logger.warn(`Redis: Đang thử kết nối lại (lần ${times}), thử lại sau ${delay}ms.`)
        return delay
      }
    })

    client.on('error', (err) => {
      logger.error('Redis Client Error:', err)
    })

    return client
  }
}

const sharedServices = [
  PrismaService,
  HashingService,
  TokenService,
  EmailService,
  SharedUserRepository,
  SharedRoleRepository,
  TwoFactorService,
  CookieService,
  CryptoService,
  UserAgentService,
  RedisService,
  GeolocationService,
  DeviceFingerprintService,
  SessionService,
  SltService,
  PaginationService,
  S3Service
]

const sharedMiddlewares = [CsrfProtectionMiddleware, SecurityHeadersMiddleware]

const sharedGuards = [AccessTokenGuard, PaymentAPIKeyGuard, AuthenticationGuard]

const allProviders = [
  ...sharedServices,
  ...sharedMiddlewares,
  ...sharedGuards,
  redisClientProvider,
  {
    provide: APP_GUARD,
    useClass: AuthenticationGuard
  }
]

@Global()
@Module({
  imports: [JwtModule],
  providers: allProviders,
  exports: [...sharedServices, ...sharedMiddlewares, ...sharedGuards]
})
export class SharedModule {}
