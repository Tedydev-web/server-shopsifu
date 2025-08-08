import { Global, Module } from '@nestjs/common'
import { PrismaService } from 'src/shared/services/prisma.service'
import { HashingService } from './services/hashing.service'
import { TokenService } from './services/token.service'
import { CookieService } from './services/cookie.service'
import { JwtModule } from '@nestjs/jwt'
import { AccessTokenGuard } from 'src/shared/guards/access-token.guard'
import { PaymentAPIKeyGuard } from 'src/shared/guards/payment-api-key.guard'
import { APP_GUARD } from '@nestjs/core'
import { AuthenticationGuard } from 'src/shared/guards/authentication.guard'
import { SharedUserRepository } from 'src/shared/repositories/shared-user.repo'
import { EmailService } from 'src/shared/services/email.service'
import { TwoFactorService } from 'src/shared/services/2fa.service'
import { SharedRoleRepository } from 'src/shared/repositories/shared-role.repo'
import { S3Service } from 'src/shared/services/s3.service'
import { SharedPaymentRepository } from './repositories/shared-payment.repo'
import { SharedWebsocketRepository } from './repositories/shared-websocket.repo'
import path from 'path'
import { existsSync } from 'fs'
import { AcceptLanguageResolver, I18nModule, QueryResolver } from 'nestjs-i18n'
import { Resolvable, ThrottlerModule, ThrottlerModuleOptions } from '@nestjs/throttler'
import { ScheduleModule } from '@nestjs/schedule'
import { BullModule } from '@nestjs/bullmq'
import { CacheModule } from '@nestjs/cache-manager'
import { LoggerModule } from 'nestjs-pino'
import { ConfigModule, ConfigService } from '@nestjs/config'
import { createKeyv } from '@keyv/redis'
import configs from 'src/shared/config'
import { createLoggerConfig } from './config/logger.config'
import { PaymentProducer } from './producers/payment.producer'
import { PAYMENT_QUEUE_NAME } from './constants/queue.constant'
import { ElasticsearchService } from './services/elasticsearch.service'
import { SearchSyncService } from './services/search-sync.service'
import { SearchSyncConsumer } from './consumers/search-sync.consumer'
import { SEARCH_SYNC_QUEUE_NAME } from './constants/search-sync.constant'
import { PaymentConsumer } from './consumers/payment.consumer'
import { MetricsService } from './services/metrics.service'

const sharedServices = [
  PrismaService,
  HashingService,
  TokenService,
  CookieService,
  EmailService,
  SharedUserRepository,
  TwoFactorService,
  SharedRoleRepository,
  SharedPaymentRepository,
  SharedWebsocketRepository,
  S3Service,
  PaymentProducer,
  ElasticsearchService,
  SearchSyncService,
  SearchSyncConsumer,
  PaymentConsumer,
  MetricsService
]

@Global()
@Module({
  providers: [
    ...sharedServices,
    AccessTokenGuard,
    PaymentAPIKeyGuard,
    {
      provide: APP_GUARD,
      useClass: AuthenticationGuard
    }
  ],
  exports: sharedServices,
  imports: [
    // Configuration - Global
    ConfigModule.forRoot({
      load: configs,
      isGlobal: true,
      cache: true,
      envFilePath: ['.env'],
      expandVariables: true
    }),

    LoggerModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: createLoggerConfig
    }),

    // Schedule Module - Cronjobs
    ScheduleModule.forRoot(),

    // Internationalization - I18n
    I18nModule.forRoot({
      fallbackLanguage: 'en',
      loaderOptions: {
        // Tự động chọn thư mục ngôn ngữ: ưu tiên dist khi chạy production, fallback sang src khi dev
        path: (() => {
          const distLang = path.resolve('dist/shared/languages')
          const srcLang = path.resolve('src/shared/languages')
          if (existsSync(distLang)) return distLang
          if (existsSync(srcLang)) return srcLang
          return path.join(__dirname, 'languages')
        })(),
        watch: process.env.NODE_ENV !== 'production'
      },
      resolvers: [{ use: QueryResolver, options: ['lang'] }, AcceptLanguageResolver],
      // Luôn generate types để đảm bảo type safety
      typesOutputPath: path.resolve('src/shared/languages/generated/i18n.generated.ts')
    }),

    CacheModule.registerAsync({
      isGlobal: true,
      useFactory: () => {
        return {
          stores: [createKeyv(process.env.REDIS_URL)]
        }
      }
    }),

    // Queue Management - Bull/Redis
    BullModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: (configService: ConfigService) => ({
        connection: {
          host: configService.get('redis.host'),
          port: Number(configService.get('redis.port')),
          password: configService.get('redis.password')
        }
      }),
      inject: [ConfigService]
    }),

    // Payment Queue
    BullModule.registerQueue({
      name: PAYMENT_QUEUE_NAME
    }),

    // Search Sync Queue
    BullModule.registerQueue({
      name: SEARCH_SYNC_QUEUE_NAME
    }),

    // Rate Limiting - Throttler
    ThrottlerModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: (configService: ConfigService): ThrottlerModuleOptions => ({
        throttlers: [
          {
            ttl: configService.get('app.throttle.ttl') as Resolvable<number>,
            limit: configService.get('app.throttle.limit') as Resolvable<number>
          }
        ]
      }),
      inject: [ConfigService]
    }),
    JwtModule
  ]
})
export class SharedModule {}
