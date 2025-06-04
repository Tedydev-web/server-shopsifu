import { Global, Module } from '@nestjs/common'
import { PrismaService } from './services/prisma.service'
import { HashingService } from './services/hashing.service'
import { EmailService } from './services/email.service'
import { APP_GUARD, APP_INTERCEPTOR, APP_PIPE } from '@nestjs/core'
import { AccessTokenGuard } from 'src/routes/auth/guards/access-token.guard'
import { APIKeyGuard } from './guards/api-key.guard'
import { AuthenticationGuard } from './guards/authentication.guard'
import { ZodSerializerInterceptor } from 'nestjs-zod'
import CustomZodValidationPipe from './pipes/custom-zod-validation.pipe'
import { CacheModule } from '@nestjs/cache-manager'
import { ConfigService } from '@nestjs/config'
import { GeolocationService } from './services/geolocation.service'
import { TransformInterceptor } from './interceptor/transform.interceptor'
import { CryptoService } from './services/crypto.service'
import { RedisProviderModule } from './providers/redis/redis.module'
import { RedisService } from './providers/redis/redis.service'

const SHARED_PIPES = [
  {
    provide: APP_PIPE,
    useClass: CustomZodValidationPipe
  }
]

const SHARED_INTERCEPTORS = [
  { provide: APP_INTERCEPTOR, useClass: ZodSerializerInterceptor },
  { provide: APP_INTERCEPTOR, useClass: TransformInterceptor }
]

// Concrete guard classes that can be provided and exported
const CONCRETE_GUARDS = [AccessTokenGuard, APIKeyGuard, AuthenticationGuard]

const SHARED_SERVICES = [PrismaService, HashingService, EmailService, CryptoService, RedisService]

@Global()
@Module({
  imports: [
    RedisProviderModule,
    CacheModule.registerAsync({
      isGlobal: true,
      useFactory: (configService: ConfigService) => ({
        store: 'redis',
        host: configService.get<string>('REDIS_HOST'),
        port: configService.get<number>('REDIS_PORT'),
        password: configService.get<string>('REDIS_PASSWORD'),
        ttl: configService.get<number>('CACHE_TTL', 60)
      }),
      inject: [ConfigService]
    })
  ],
  providers: [
    ...SHARED_SERVICES,
    ...CONCRETE_GUARDS, // Provide concrete guards
    ...SHARED_PIPES,
    ...SHARED_INTERCEPTORS,
    {
      // Register AuthenticationGuard as a global APP_GUARD
      provide: APP_GUARD,
      useClass: AuthenticationGuard
    },
    GeolocationService,
    CryptoService
  ],
  // Export concrete services and guards for other modules to inject if needed
  exports: [
    ...SHARED_SERVICES,
    ...CONCRETE_GUARDS,
    CacheModule,
    APIKeyGuard,
    GeolocationService,
    CryptoService,
    RedisProviderModule
  ]
})
export class SharedModule {}
