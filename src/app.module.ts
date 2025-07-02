import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common'
import { SharedModule } from './shared/shared.module'
import { AuthModule } from './routes/auth/auth.module'
import { APP_FILTER, APP_GUARD, APP_INTERCEPTOR, APP_PIPE } from '@nestjs/core'
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
import { UserModule } from './routes/user/user.module'
import { MediaModule } from './routes/media/media.module'
import { BrandModule } from './routes/brand/brand.module'
import { BrandTranslationModule } from './routes/brand/brand-translation/brand-translation.module'
import { CategoryTranslationModule } from './routes/category/category-translation/category-translation.module'
import { CategoryModule } from './routes/category/category.module'
import { HttpExceptionFilter } from './shared/filters/http-exception.filter'

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      load: [envConfig],
    }),
    I18nModule.forRoot({
      fallbackLanguage: 'en',
      loaderOptions: {
        path: path.resolve('src/i18n/'),
        watch: true,
      },
      resolvers: [{ use: QueryResolver, options: ['lang'] }, AcceptLanguageResolver],
      typesOutputPath: path.resolve('src/generated/i18n.generated.ts'),
    }),
    // ThrottlerModule.forRoot([
    //   {
    //     ttl: 60000,
    //     limit: 10,
    //   },
    // ]),
    SharedModule,
    AuthModule,
    LanguageModule,
    PermissionModule,
    RoleModule,
    ProfileModule,
    UserModule,
    MediaModule,
    BrandModule,
    BrandTranslationModule,
    CategoryModule,
    CategoryTranslationModule,
  ],
  providers: [
    {
      provide: APP_PIPE,
      useClass: CustomZodValidationPipe,
    },
    { provide: APP_INTERCEPTOR, useClass: ZodSerializerInterceptor },
    {
      provide: APP_FILTER,
      useClass: HttpExceptionFilter,
    },
  ],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(CsrfProtectionMiddleware).forRoutes('*')
  }
}
