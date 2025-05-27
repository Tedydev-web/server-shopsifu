import { Module, NestModule, MiddlewareConsumer, RequestMethod } from '@nestjs/common'
import { ConfigModule } from '@nestjs/config'
import { AppController } from './app.controller'
import { AppService } from './app.service'
import { SharedModule } from 'src/shared/shared.module'
import { AuthModule } from 'src/routes/auth/auth.module'
import { APP_PIPE, APP_INTERCEPTOR, APP_FILTER, APP_GUARD } from '@nestjs/core'
import CustomZodValidationPipe from 'src/shared/pipes/custom-zod-validation.pipe'
import { ZodSerializerInterceptor } from 'nestjs-zod'
import { LanguageModule } from './routes/language/language.module'
import { AuditLogModule } from './routes/audit-log/audit-log.module'
import { SecurityHeadersMiddleware } from './shared/middleware/security-headers.middleware'
import { CsrfMiddleware } from './shared/middleware/csrf.middleware'
import { ThrottlerModule, ThrottlerGuard } from '@nestjs/throttler'
import { LoggerMiddleware } from './shared/middleware/logger.middleware'
import { PermissionModule } from './routes/permission/permission.module'
import { RoleModule } from './routes/role/role.module'
import { AcceptLanguageResolver, I18nModule, QueryResolver, HeaderResolver } from 'nestjs-i18n'
import path from 'path'
import { AllExceptionsFilter } from './shared/filters/all-exceptions.filter'
import envConfig from './shared/config'
import { WinstonModule } from 'nest-winston'
import { dailyRotateFileTransport, consoleTransport } from './shared/logger/winston.config'
import { RedisProviderModule } from './shared/providers/redis/redis.module'
import { TokenRefreshInterceptor } from 'src/routes/auth/interceptors/token-refresh.interceptor'
import { AuditLogInterceptor } from './shared/interceptor/audit-log.interceptor'
import { PasswordReverificationGuard } from './routes/auth/guards/password-reverification.guard'

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      load: [() => envConfig],
      cache: true
    }),
    ThrottlerModule.forRoot([
      {
        name: 'short',
        ttl: 1000,
        limit: 10
      },
      {
        name: 'medium',
        ttl: 10000,
        limit: 40
      },
      {
        name: 'long',
        ttl: 60000,
        limit: 100
      }
    ]),
    I18nModule.forRoot({
      fallbackLanguage: 'en',
      loaderOptions: {
        path: path.join(__dirname, '../i18n/'),
        watch: true
      },
      resolvers: [new QueryResolver(['lang', 'l']), AcceptLanguageResolver, new HeaderResolver(['x-lang'])]
    }),
    WinstonModule.forRoot({
      transports: [consoleTransport(), dailyRotateFileTransport('error'), dailyRotateFileTransport('info')]
    }),
    SharedModule,
    RedisProviderModule,
    AuthModule,
    AuditLogModule,
    RoleModule,
    PermissionModule,
    LanguageModule
  ],
  controllers: [AppController],
  providers: [
    AppService,
    {
      provide: APP_PIPE,
      useClass: CustomZodValidationPipe
    },
    { provide: APP_INTERCEPTOR, useClass: ZodSerializerInterceptor },
    {
      provide: APP_INTERCEPTOR,
      useClass: TokenRefreshInterceptor
    },
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard
    },
    {
      provide: APP_INTERCEPTOR,
      useClass: AuditLogInterceptor
    },
    {
      provide: APP_GUARD,
      useClass: PasswordReverificationGuard
    },
    { provide: APP_FILTER, useClass: AllExceptionsFilter }
  ]
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(LoggerMiddleware).forRoutes('*')
    consumer.apply(SecurityHeadersMiddleware).forRoutes('*')
    consumer.apply(CsrfMiddleware).forRoutes({ path: '*', method: RequestMethod.ALL })
  }
}
