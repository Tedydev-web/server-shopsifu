import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common'
import { APP_FILTER, APP_GUARD, APP_INTERCEPTOR } from '@nestjs/core'
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
import { RoleModule } from './routes/role/role.module'
import { PermissionModule } from './routes/permission/permission.module'
import { UserModule } from './routes/user/user.module'
import { CaslModule } from './shared/casl/casl.module'
import { AllExceptionsFilter } from './shared/filters/all-exceptions.filter'
import { ResponseInterceptor } from './shared/interceptors/response.interceptor'

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true, load: [appConfig] }),
    I18nModule.forRoot({
      fallbackLanguage: 'vi',
      loaderOptions: {
        path: path.resolve('src/i18n'),
        watch: true
      },
      resolvers: [AcceptLanguageResolver, { use: QueryResolver, options: ['lang'] }],
      typesOutputPath: path.resolve('src/generated/i18n.generated.ts')
    }),
    SharedModule,
    AuthModule,
    ProfileModule,
    ThrottlerModule.forRoot([
      {
        ttl: 60000, // 60 seconds
        limit: 10 // 10 requests per 60 seconds per IP
      }
    ]),
    RoleModule,
    PermissionModule,
    UserModule,
    CaslModule
  ],
  controllers: [AppController],
  providers: [
    AppService,
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard
    },
    {
      provide: APP_FILTER,
      useClass: AllExceptionsFilter
    },
    {
      provide: APP_INTERCEPTOR,
      useClass: ResponseInterceptor
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
