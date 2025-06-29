import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common'
import { SharedModule } from './shared/shared.module'
import { AuthModule } from './routes/auth/auth.module'
import { APP_FILTER, APP_GUARD, APP_INTERCEPTOR, APP_PIPE } from '@nestjs/core'
import { AllExceptionsFilter } from 'src/shared/filters/all-exceptions.filter'
import { LanguageModule } from 'src/routes/language/language.module'
import { ConfigModule } from '@nestjs/config'
import { CsrfProtectionMiddleware } from 'src/shared/middleware/csrf.middleware'
import { AcceptLanguageResolver, I18nModule, QueryResolver } from 'nestjs-i18n'
import path from 'path'
import { TransformInterceptor } from './shared/interceptor/transform.interceptor'
import { ThrottlerGuard, ThrottlerModule } from '@nestjs/throttler'
import { PermissionModule } from './routes/permission/permission.module'
import { RoleModule } from './routes/role/role.module'
import envConfig from 'src/shared/config'
import { ProfileModule } from './routes/profile/profile.module'
import { ZodSerializerInterceptor } from 'nestjs-zod'
import CustomZodValidationPipe from 'src/shared/pipes/custom-zod-validation.pipe'

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      load: [envConfig],
    }),
    I18nModule.forRoot({
      fallbackLanguage: 'vi',
      loaderOptions: {
        path: path.resolve('src/i18n'),
        watch: true,
      },
      resolvers: [AcceptLanguageResolver, new QueryResolver(['lang'])],
      typesOutputPath: path.resolve('src/generated/i18n.generated.ts'),
    }),
    ThrottlerModule.forRoot([
      {
        ttl: 60000,
        limit: 10,
      },
    ]),
    SharedModule,
    AuthModule,
    LanguageModule,
    PermissionModule,
    RoleModule,
    ProfileModule,
  ],
  providers: [
    {
      provide: APP_PIPE,
      useClass: CustomZodValidationPipe,
    },
    {
      provide: APP_INTERCEPTOR,
      useClass: TransformInterceptor,
    },
    {
      provide: APP_INTERCEPTOR,
      useClass: ZodSerializerInterceptor,
    },
    {
      provide: APP_FILTER,
      useClass: AllExceptionsFilter,
    },
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard,
    },
  ],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(CsrfProtectionMiddleware).forRoutes('*')
  }
}
