import { Module, NestModule, MiddlewareConsumer, RequestMethod } from '@nestjs/common'
import { ConfigModule } from '@nestjs/config'
import { APP_PIPE, APP_INTERCEPTOR, APP_FILTER } from '@nestjs/core'
import { ZodSerializerInterceptor } from 'nestjs-zod'
import { AcceptLanguageResolver, QueryResolver, HeaderResolver, I18nModule } from 'nestjs-i18n'
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
import { InterceptorsModule } from './shared/interceptor/interceptors.module'
import { MiddlewaresModule } from './shared/middleware/middlewares.module'
import { GuardsModule } from './shared/guards/guards.module'

// Auth components
import { AuthModule } from './routes/auth/auth.module'

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

    // 2. Logger
    WinstonModule.forRoot({
      transports: [consoleTransport(), dailyRotateFileTransport('error'), dailyRotateFileTransport('info')]
    }),

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

    // 4. Core Modules
    SharedModule,
    MiddlewaresModule,
    GuardsModule,
    InterceptorsModule,

    // 5. Cuối cùng phải là AuthModule
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
      provide: APP_FILTER,
      useClass: AllExceptionsFilter
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
