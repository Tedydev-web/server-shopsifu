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

@Module({
  imports: [
    SharedModule,
    AuthModule,
    LanguageModule,
    ThrottlerModule.forRoot([
      {
        name: 'short',
        ttl: 1000, // 1 giây
        limit: 3 // 3 requests mỗi giây
      },
      {
        name: 'medium',
        ttl: 10000, // 10 giây
        limit: 20 // 20 requests mỗi 10 giây
      },
      {
        name: 'long',
        ttl: 60000, // 1 phút
        limit: 100 // 100 requests mỗi phút
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
      provide: APP_GUARD, // Đăng ký ThrottlerGuard global
      useClass: ThrottlerGuard
    }
  ]
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(SecurityHeadersMiddleware).forRoutes('*').apply(CsrfMiddleware).forRoutes('*')
  }
}
