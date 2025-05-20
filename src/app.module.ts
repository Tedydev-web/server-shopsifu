import { Module, NestModule, MiddlewareConsumer } from '@nestjs/common'
import { AppController } from './app.controller'
import { AppService } from './app.service'
import { SharedModule } from 'src/shared/shared.module'
import { AuthModule } from 'src/routes/auth/auth.module'
import { APP_GUARD, APP_INTERCEPTOR, APP_PIPE } from '@nestjs/core'
import CustomZodValidationPipe from 'src/shared/pipes/custom-zod-validation.pipe'
import { ZodSerializerInterceptor } from 'nestjs-zod'
import { LanguageModule } from './routes/language/language.module'
import { SecurityHeadersMiddleware } from './shared/middleware/security-headers.middleware'
import { CsrfMiddleware } from './shared/middleware/csrf.middleware'
import { ThrottlerModule, ThrottlerGuard } from '@nestjs/throttler'
import { LoggerMiddleware } from './shared/middleware/logger.middleware'
import { TokenRefreshInterceptor } from './shared/interceptor/token-refresh.interceptor'

@Module({
  imports: [
    SharedModule,
    AuthModule,
    LanguageModule,
    ThrottlerModule.forRoot([
      {
        name: 'short',
        ttl: 1000,
        limit: 3
      },
      {
        name: 'medium',
        ttl: 10000,
        limit: 20
      },
      {
        name: 'long',
        ttl: 60000,
        limit: 100
      }
    ])
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
    }
  ]
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(LoggerMiddleware).forRoutes('*')
    consumer.apply(SecurityHeadersMiddleware).forRoutes('*').apply(CsrfMiddleware).forRoutes('*')
  }
}
