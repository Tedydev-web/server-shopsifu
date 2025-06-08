import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common'
import { APP_GUARD } from '@nestjs/core'
import { ThrottlerGuard, ThrottlerModule } from '@nestjs/throttler'
import { ConfigModule } from '@nestjs/config'
import appConfig from './shared/config'
import { AppController } from './app.controller'
import { AppService } from './app.service'
import { CsrfMiddleware, LoggerMiddleware, SecurityHeadersMiddleware } from './shared/middleware'
import { AuthModule } from './routes/auth/auth.module'
import { I18nModule, AcceptLanguageResolver, QueryResolver } from 'nestjs-i18n'
import path from 'path'
import { ProfileModule } from './routes/profile/profile.module'
import { SharedModule } from './shared/shared.module'
import { RedisProviderModule } from './shared/providers/redis/redis.module'

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true, load: [appConfig] }),
    I18nModule.forRoot({
      fallbackLanguage: 'vi',
      loaderOptions: {
        path: path.resolve('src/i18n/'),
        watch: true
      },
      resolvers: [{ use: QueryResolver, options: ['lang'] }, AcceptLanguageResolver],
      typesOutputPath: path.resolve('src/generated/i18n.generated.ts')
    }),
    SharedModule,
    RedisProviderModule,
    AuthModule,
    ProfileModule,
    ThrottlerModule.forRoot([
      {
        ttl: 60000, // 60 seconds
        limit: 10 // 10 requests per 60 seconds per IP
      }
    ])
  ],
  controllers: [AppController],
  providers: [
    AppService,
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard
    }
  ]
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(LoggerMiddleware).forRoutes('*')
    consumer.apply(SecurityHeadersMiddleware).forRoutes('*')
    consumer.apply(CsrfMiddleware).forRoutes('*')
  }
}
