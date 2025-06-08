import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common'
import { APP_GUARD } from '@nestjs/core'
import { AppController } from './app.controller'
import { AppService } from './app.service'
import { AuthenticationGuard } from './shared/guards/authentication.guard'
import { CsrfMiddleware, LoggerMiddleware, SecurityHeadersMiddleware } from './shared/middleware'
import { AuthModule } from './routes/auth/auth.module'
import { SessionsModule } from './routes/auth/modules/sessions/session.module'
import { I18nModule, AcceptLanguageResolver, QueryResolver } from 'nestjs-i18n'
import path from 'path'
import { ProfileModule } from './routes/profile/profile.module'

@Module({
  imports: [
    I18nModule.forRoot({
      fallbackLanguage: 'vi',
      loaderOptions: {
        path: path.resolve('src/i18n/'),
        watch: true
      },
      resolvers: [{ use: QueryResolver, options: ['lang'] }, AcceptLanguageResolver],
      typesOutputPath: path.resolve('src/generated/i18n.generated.ts')
    }),
    AuthModule,
    SessionsModule,
    ProfileModule
  ],
  controllers: [AppController],
  providers: [
    AppService,
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
