import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common'
import { ConfigModule, ConfigService } from '@nestjs/config'
import { APP_FILTER, APP_GUARD, APP_INTERCEPTOR, APP_PIPE } from '@nestjs/core'
import { ScheduleModule } from '@nestjs/schedule'
import { ThrottlerGuard, ThrottlerModule } from '@nestjs/throttler'
import { I18nModule, AcceptLanguageResolver, QueryResolver } from 'nestjs-i18n'
import path from 'path'

import { AppController } from './app.controller'
import { AppService } from './app.service'

// Shared components
import { AllExceptionsFilter } from './shared/filters/all-exceptions.filter'
import CustomZodValidationPipe from './shared/pipes/custom-zod-validation.pipe'
import { AuthenticationGuard } from './shared/guards/authentication.guard'
import { TransformInterceptor } from './shared/interceptor/transform.interceptor'

// Middlewares
import { CsrfMiddleware, LoggerMiddleware, SecurityHeadersMiddleware } from './shared/middleware'

// Modules
import { SharedModule } from './shared/shared.module'

// Routes
import { AuthModule } from './routes/auth/auth.module'

// Config
import appConfig from './shared/config'

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      load: [appConfig],
      envFilePath: ['.env']
    }),
    I18nModule.forRoot({
      fallbackLanguage: 'vi',
      loaderOptions: {
        path: path.resolve('src/i18n/'),
        watch: true
      },
      resolvers: [{ use: QueryResolver, options: ['lang'] }, AcceptLanguageResolver],
      typesOutputPath: path.resolve('src/generated/i18n.generated.ts')
    }),
    ThrottlerModule.forRoot([
      {
        ttl: 60000, // 60 seconds
        limit: 10 // 10 requests per 60 seconds
      }
    ]),
    ScheduleModule.forRoot(),
    SharedModule,
    AuthModule
  ],
  controllers: [AppController],
  providers: [
    AppService,
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard
    },
    {
      provide: APP_GUARD,
      useClass: AuthenticationGuard
    },
    {
      provide: APP_FILTER,
      useClass: AllExceptionsFilter
    },
    {
      provide: APP_PIPE,
      useClass: CustomZodValidationPipe
    },
    {
      provide: APP_INTERCEPTOR,
      useClass: TransformInterceptor
    }
  ]
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(LoggerMiddleware).forRoutes('*')
    consumer.apply(SecurityHeadersMiddleware).forRoutes('*')
    consumer.apply(CsrfMiddleware).forRoutes('*') // Áp dụng CSRF cho tất cả các routes
  }
}
