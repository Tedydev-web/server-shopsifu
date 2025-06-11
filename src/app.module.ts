import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common'
import { ConfigModule } from '@nestjs/config'
import { APP_FILTER, APP_GUARD, APP_INTERCEPTOR } from '@nestjs/core'
import { ThrottlerGuard, ThrottlerModule } from '@nestjs/throttler'
import { AcceptLanguageResolver, I18nModule, QueryResolver } from 'nestjs-i18n'
import path from 'path'
import { AppController } from './app.controller'
import { AppService } from './app.service'
import { AuthModule } from './routes/auth/auth.module'
import { PermissionModule } from './routes/permission/permission.module'
import { ProfileModule } from './routes/profile/profile.module'
import { RoleModule } from './routes/role/role.module'
import { UserModule } from './routes/user/user.module'
import { CaslModule } from './shared/providers/casl/casl.module'
import { ClsModule } from './shared/providers/cls/cls.module'
import appConfig from './shared/config'
import { AllExceptionsFilter } from './shared/filters/all-exceptions.filter'
import { ResponseInterceptor } from './shared/interceptors/response.interceptor'
import { CsrfMiddleware, LoggerMiddleware, SecurityHeadersMiddleware } from './shared/middleware'
import { MiddlewaresModule } from './shared/middleware/middlewares.module'
import { SharedModule } from './shared/shared.module'
import { AuthenticationGuard } from './routes/auth/guards/authentication.guard'

@Module({
  imports: [
    ClsModule,
    ConfigModule.forRoot({
      isGlobal: true,
      load: [appConfig]
    }),
    I18nModule.forRoot({
      fallbackLanguage: 'en',
      loaderOptions: {
        path: path.resolve('src/i18n'),
        watch: true
      },
      resolvers: [AcceptLanguageResolver, new QueryResolver(['lang'])],
      typesOutputPath: path.resolve('src/generated/i18n.generated.ts')
    }),
    ThrottlerModule.forRoot([
      {
        ttl: 60000,
        limit: 10
      }
    ]),
    SharedModule,
    AuthModule,
    PermissionModule,
    UserModule,
    RoleModule,
    ProfileModule,
    CaslModule,
    MiddlewaresModule
  ],
  controllers: [AppController],
  providers: [
    AppService,
    {
      provide: APP_FILTER,
      useClass: AllExceptionsFilter
    },
    {
      provide: APP_INTERCEPTOR,
      useClass: ResponseInterceptor
    },
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard
    },
    {
      provide: APP_GUARD,
      useClass: AuthenticationGuard
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
