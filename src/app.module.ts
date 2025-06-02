import { Module, NestModule, MiddlewareConsumer, RequestMethod } from '@nestjs/common'
import { ConfigModule } from '@nestjs/config'
import { APP_PIPE, APP_INTERCEPTOR, APP_FILTER, APP_GUARD } from '@nestjs/core'
import { ThrottlerModule, ThrottlerGuard } from '@nestjs/throttler'
import { ZodSerializerInterceptor } from 'nestjs-zod'
import { AcceptLanguageResolver, I18nModule, QueryResolver, HeaderResolver } from 'nestjs-i18n'
import { WinstonModule } from 'nest-winston'
import path from 'path'

// App components
import { AppController } from './app.controller'
import { AppService } from './app.service'

// Shared components
import { SharedModule } from './shared/shared.module'
import CustomZodValidationPipe from './shared/pipes/custom-zod-validation.pipe'
import { SecurityHeadersMiddleware } from './shared/middleware/security-headers.middleware'
import { CsrfMiddleware } from './shared/middleware/csrf.middleware'
import { LoggerMiddleware } from './shared/middleware/logger.middleware'
import { AllExceptionsFilter } from './shared/filters/all-exceptions.filter'
import envConfig from './shared/config'
import { dailyRotateFileTransport, consoleTransport } from './shared/logger/winston.config'
import { RedisProviderModule } from './shared/providers/redis/redis.module'

// Auth components
import { AuthModule } from './routes/auth/auth.module'
import { TokenRefreshInterceptor } from './routes/auth/interceptors/token-refresh.interceptor'
import { AuthenticationGuard } from './shared/guards/authentication.guard'

// Tạm thời comment lại cho đến khi module được tạo
// import { ProfileModule } from './routes/profile/profile.module'

@Module({
  imports: [
    // 1. Configs
    ConfigModule.forRoot({
      isGlobal: true,
      load: [() => envConfig],
      cache: true
    }),

    // 2. Utils và Interceptors
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

    // 3. I18n
    I18nModule.forRoot({
      fallbackLanguage: 'en',
      loaderOptions: {
        path: path.join(__dirname, '../i18n/'),
        watch: true
      },
      resolvers: [new QueryResolver(['lang', 'l']), AcceptLanguageResolver, new HeaderResolver(['x-lang'])],
      typesOutputPath: path.resolve('src/generated/i18n.generated.ts')
    }),

    // 4. Logger
    WinstonModule.forRoot({
      transports: [consoleTransport(), dailyRotateFileTransport('error'), dailyRotateFileTransport('info')]
    }),

    // 5. Shared
    SharedModule,

    // 6. Cuối cùng phải là AuthModule
    AuthModule.register({ isGlobal: true })
    // Tạm thời comment lại
    // ProfileModule
  ],
  controllers: [AppController],
  providers: [
    AppService,
    {
      provide: APP_PIPE,
      useClass: CustomZodValidationPipe
    },
    {
      provide: APP_INTERCEPTOR,
      useClass: ZodSerializerInterceptor
    },
    {
      provide: APP_INTERCEPTOR,
      useClass: TokenRefreshInterceptor
    },
    {
      provide: APP_FILTER,
      useClass: AllExceptionsFilter
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
    consumer
      .apply(SecurityHeadersMiddleware, CsrfMiddleware, LoggerMiddleware)
      .exclude(
        { path: 'api-docs', method: RequestMethod.ALL },
        { path: 'api-docs/(.*)', method: RequestMethod.ALL },
        { path: 'public/(.*)', method: RequestMethod.GET }
      )
      .forRoutes('*')
  }
}
