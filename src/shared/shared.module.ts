import { Global, Module, Logger } from '@nestjs/common'
import { PrismaService } from './services/prisma.service'
import { HashingService } from './services/hashing.service'
import { EmailService } from './services/email.service'
import { APP_GUARD, APP_INTERCEPTOR, APP_PIPE, APP_FILTER } from '@nestjs/core'
// import { AccessTokenGuard } from './guards/auth/access-token.guard'
import { ApiKeyGuard } from './guards/auth/api-key.guard'
import { AuthenticationGuard } from './guards/authentication.guard'
import { ZodSerializerInterceptor } from 'nestjs-zod'
import CustomZodValidationPipe from './pipes/custom-zod-validation.pipe'
import { CacheModule } from '@nestjs/cache-manager'
import { ConfigModule, ConfigService } from '@nestjs/config'
import { GeolocationService } from './services/geolocation.service'
import { TransformInterceptor } from './interceptor/transform.interceptor'
import { CryptoService } from './services/crypto.service'
import { RedisProviderModule } from './providers/redis/redis.module'
import { RedisService } from './providers/redis/redis.service'
import { CookieService } from './services/cookie.service'
import { TokenService } from './services/token.service'
import { JwtModule } from '@nestjs/jwt'
import { COOKIE_SERVICE, TOKEN_SERVICE, EMAIL_SERVICE, LOGGER_SERVICE, SLT_SERVICE } from './constants/injection.tokens'
import { GuardsModule } from './guards/guards.module'
import { TokenRefreshInterceptor } from './interceptor/auth/token-refresh.interceptor'
import { UserAuthRepository } from './repositories/auth/user-auth.repository'
import { SessionRepository } from './repositories/auth/session.repository'
import { DeviceRepository } from './repositories/auth/device.repository'
import { RecoveryCodeRepository } from './repositories/auth/recovery-code.repository'
import { DeviceService } from './services/auth/device.service'
import { UserActivityService } from './services/auth/user-activity.service'
import { WinstonModule } from 'nest-winston'
import { WinstonConfig } from './logger/winston.config'
import { AuthVerificationService } from './services/auth/auth-verification.service'
import { AllExceptionsFilter } from './filters/all-exceptions.filter'
import { SLTService } from './services/auth/slt.service'

const SHARED_PIPES = [
  {
    provide: APP_PIPE,
    useClass: CustomZodValidationPipe
  }
]

const SHARED_INTERCEPTORS = [
  { provide: APP_INTERCEPTOR, useClass: ZodSerializerInterceptor },
  { provide: APP_INTERCEPTOR, useClass: TransformInterceptor },
  { provide: APP_INTERCEPTOR, useClass: TokenRefreshInterceptor }
]

const SHARED_SERVICES = [
  PrismaService,
  HashingService,
  {
    provide: EMAIL_SERVICE,
    useClass: EmailService
  },
  CryptoService,
  RedisService,
  GeolocationService,
  {
    provide: COOKIE_SERVICE,
    useClass: CookieService
  },
  {
    provide: TOKEN_SERVICE,
    useClass: TokenService
  },
  {
    provide: SLT_SERVICE,
    useClass: SLTService
  },
  SLTService,
  UserAuthRepository,
  SessionRepository,
  DeviceRepository,
  RecoveryCodeRepository,
  DeviceService,
  UserActivityService
]

@Global()
@Module({
  imports: [
    ConfigModule,
    RedisProviderModule,
    GuardsModule,
    WinstonModule.forRootAsync({
      useFactory: () => {
        return WinstonConfig
      }
    }),
    JwtModule.registerAsync({
      useFactory: (configService: ConfigService) => ({
        secret: configService.get<string>('ACCESS_TOKEN_SECRET'),
        signOptions: { expiresIn: configService.get<string>('ACCESS_TOKEN_EXPIRES_IN', '15m') }
      }),
      inject: [ConfigService],
      global: true
    }),
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
    ...SHARED_PIPES,
    ...SHARED_INTERCEPTORS,
    {
      provide: APP_GUARD,
      useClass: AuthenticationGuard
    },
    Logger,
    {
      provide: LOGGER_SERVICE,
      useFactory: (logger: Logger) => logger,
      inject: [Logger]
    },
    AuthVerificationService,
    {
      provide: APP_FILTER,
      useClass: AllExceptionsFilter
    },
    {
      provide: APP_INTERCEPTOR,
      useClass: TransformInterceptor
    }
  ],
  // Export concrete services and guards for other modules to inject if needed
  exports: [
    ...SHARED_SERVICES,
    CacheModule,
    JwtModule,
    GuardsModule,
    CryptoService,
    RedisProviderModule,
    LOGGER_SERVICE,
    WinstonModule,
    Logger,
    AuthVerificationService
  ]
})
export class SharedModule {}
