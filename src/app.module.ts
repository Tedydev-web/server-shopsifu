import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common'
import { APP_GUARD } from '@nestjs/core'
import { AppController } from './app.controller'
import { AppService } from './app.service'
import { AuthenticationGuard } from './routes/auth/shared/guards/authentication.guard'
import { CsrfMiddleware, LoggerMiddleware, SecurityHeadersMiddleware } from './shared/middleware'
import { AuthModule } from './routes/auth/auth.module'
import { CoreModule } from './core/core.module'
import { GuardsModule } from './routes/auth/shared/guards/guards.module'
import { JwtAuthGuard } from './routes/auth/shared/guards/auth/jwt-auth.guard'
import { ApiKeyGuard } from './routes/auth/shared/guards/auth/api-key.guard'
import { BasicAuthGuard } from './routes/auth/shared/guards/auth/basic-auth.guard'
import { SessionsModule } from './routes/auth/modules/sessions/sessions.module'
import { SessionsService } from './routes/auth/modules/sessions/sessions.service'

@Module({
  imports: [CoreModule, AuthModule, GuardsModule, SessionsModule],
  controllers: [AppController],
  providers: [
    AppService,
    JwtAuthGuard,
    ApiKeyGuard,
    BasicAuthGuard,
    AuthenticationGuard,
    SessionsService,
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
