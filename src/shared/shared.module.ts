import { Global, Module, Logger, Provider } from '@nestjs/common'
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
import { JwtModule, JwtService } from '@nestjs/jwt'
import {
  COOKIE_SERVICE,
  TOKEN_SERVICE,
  EMAIL_SERVICE,
  LOGGER_SERVICE,
  SLT_SERVICE,
  DEVICE_SERVICE,
  REDIS_SERVICE
} from './constants/injection.tokens'
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
import { SessionsService } from 'src/routes/auth/modules/sessions/sessions.service'
import { HttpModule } from '@nestjs/axios'
import { DynamicZodSerializerInterceptor } from './interceptor/dynamic-zod-serializer.interceptor'
import * as winston from 'winston'
import { RedisClientOptions } from 'redis'
import { redisStore } from 'cache-manager-redis-store'

const SHARED_PIPES = [
  {
    provide: APP_PIPE,
    useClass: CustomZodValidationPipe
  }
]

const SHARED_INTERCEPTORS = [
  { provide: APP_INTERCEPTOR, useClass: ZodSerializerInterceptor },
  { provide: APP_INTERCEPTOR, useClass: TransformInterceptor },
  { provide: APP_INTERCEPTOR, useClass: TokenRefreshInterceptor },
  { provide: APP_INTERCEPTOR, useClass: DynamicZodSerializerInterceptor }
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
    provide: DEVICE_SERVICE,
    useClass: DeviceService
  },
  {
    provide: TOKEN_SERVICE,
    useFactory: (
      jwtService: JwtService,
      redisService: RedisService,
      configService: ConfigService,
      deviceRepository: DeviceRepository,
      sessionRepository: SessionRepository,
      cryptoService: CryptoService,
      sessionsService: SessionsService,
      deviceService: DeviceService
    ) => {
      return new TokenService(
        jwtService,
        redisService,
        configService,
        deviceRepository,
        sessionRepository,
        cryptoService,
        sessionsService,
        deviceService
      )
    },
    inject: [
      JwtService,
      REDIS_SERVICE,
      ConfigService,
      DeviceRepository,
      SessionRepository,
      CryptoService,
      SessionsService,
      DEVICE_SERVICE
    ]
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
    ConfigModule.forRoot({
      isGlobal: true
    }),
    JwtModule.register({
      secretOrKeyProvider: (requestType, tokenOrPayload, options) => {
        return process.env.JWT_SECRET || 'default-secret'
      }
    }),
    HttpModule.register({
      timeout: 5000,
      maxRedirects: 5
    }),
    GuardsModule,
    WinstonModule.forRootAsync({
      useFactory: () => ({
        transports: [
          new winston.transports.Console({
            format: winston.format.combine(winston.format.timestamp(), winston.format.prettyPrint())
          })
        ]
      })
    }),
    CacheModule.registerAsync({
      isGlobal: true,
      useFactory: (configService: ConfigService) => ({
        store: redisStore,
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
    AuthVerificationService,
    DEVICE_SERVICE,
    TOKEN_SERVICE
  ]
})
export class SharedModule {}
