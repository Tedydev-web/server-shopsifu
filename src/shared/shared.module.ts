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
import { RedisHealthService } from '../health.service'
import path from 'path'
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
import { PaymentProducer } from './queue/producer/payment.producer'
import { ShippingProducer } from './queue/producer/shipping.producer'
import { PAYMENT_QUEUE_NAME, SHIPPING_QUEUE_NAME } from './constants/queue.constant'
import { ElasticsearchService } from './services/elasticsearch.service'
import { SearchSyncService } from './services/search-sync.service'
import { SearchSyncProducer } from './queue/producer/search-sync.producer'
import { SearchSyncConsumer } from './queue/consumer/search-sync.consumer'
import { SEARCH_SYNC_QUEUE_NAME } from './constants/search-sync.constant'
import { PaymentConsumer } from './queue/consumer/payment.consumer'
import { ShippingConsumer } from './queue/consumer/shipping.consumer'
import { PricingService } from './services/pricing.service'
import { RedisService } from './services/redis.service'
import { Ghn } from 'giaohangnhanh'
import { GHN_CLIENT } from './constants/shipping.constants'
import { SharedOrderRepository } from './repositories/shared-order.repo'
import { SharedDiscountRepository } from './repositories/shared-discount.repo'
import { SharedShippingRepository } from './repositories/shared-shipping.repo'

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
  ShippingProducer,
  ElasticsearchService,
  SearchSyncService,
  SearchSyncProducer,
  SearchSyncConsumer,
  PaymentConsumer,
  ShippingConsumer,
  PricingService,
  RedisService,
  RedisHealthService,
  SharedOrderRepository,
  SharedDiscountRepository,
  SharedShippingRepository
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
    },
    {
      provide: GHN_CLIENT,
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => {
        const token = configService.getOrThrow<string>('GHN_TOKEN')
        const shopId = configService.getOrThrow<number>('GHN_SHOP_ID')
        const host = configService.getOrThrow<string>('GHN_HOST')
        const testMode = configService.getOrThrow<boolean>('GHN_TEST_MODE')
        const trackingHost = configService.getOrThrow<string>('GHN_TRACKING_HOST')
        return new Ghn({ token, shopId, host, testMode, trackingHost })
      }
    }
  ],
  exports: [...sharedServices, GHN_CLIENT],
  imports: [
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

    ScheduleModule.forRoot(),

    I18nModule.forRoot({
      fallbackLanguage: 'en',
      loaderOptions: {
        path: path.resolve('src/shared/languages/'),
        watch: true
      },
      resolvers: [{ use: QueryResolver, options: ['lang'] }, AcceptLanguageResolver],
      typesOutputPath: path.resolve('src/shared/languages/generated/i18n.generated.ts')
    }),

    CacheModule.registerAsync({
      isGlobal: true,
      useFactory: (configService: ConfigService) => {
        const redisUrl = configService.get('redis.url') || process.env.REDIS_URL
        const keyPrefix = configService.get('redis.keyPrefix') || 'shopsifu:'

        return {
          stores: [createKeyv(redisUrl, { namespace: keyPrefix })]
        }
      },
      inject: [ConfigService]
    }),

    BullModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: (configService: ConfigService) => ({
        connection: {
          host: configService.getOrThrow('redis.host'),
          port: Number(configService.getOrThrow('redis.port')),
          password: configService.getOrThrow('redis.password'),
          tls: configService.get('redis.tls') || undefined,
          requireAuth: configService.get('redis.requireAuth') || false
        },
        prefix: 'shopsifu:bull'
      }),
      inject: [ConfigService]
    }),

    BullModule.registerQueue({
      name: PAYMENT_QUEUE_NAME
    }),

    BullModule.registerQueue({
      name: SHIPPING_QUEUE_NAME
    }),

    BullModule.registerQueue({
      name: SEARCH_SYNC_QUEUE_NAME
    }),

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
