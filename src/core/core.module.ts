import { Module, Global } from '@nestjs/common'
import { ConfigModule } from '@nestjs/config'
import { APP_FILTER, APP_GUARD, APP_INTERCEPTOR, APP_PIPE } from '@nestjs/core'
import { ScheduleModule } from '@nestjs/schedule'
import { ThrottlerGuard, ThrottlerModule } from '@nestjs/throttler'
import { I18nModule, AcceptLanguageResolver, QueryResolver } from 'nestjs-i18n'
import path from 'path'
import { AllExceptionsFilter } from 'src/shared/filters/all-exceptions.filter'
import CustomZodValidationPipe from 'src/shared/pipes/custom-zod-validation.pipe'
import { TransformInterceptor } from 'src/shared/interceptor/transform.interceptor'
import appConfig from 'src/shared/config'
import { PrismaService } from 'src/shared/services/prisma.service'
import { Logger } from '@nestjs/common'
import { WinstonModule } from 'nest-winston'
import { WinstonConfig } from 'src/shared/logger/winston.config'
import { LOGGER_SERVICE } from 'src/shared/constants/injection.tokens'

@Global()
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
        ttl: 60000,
        limit: 10
      }
    ]),
    ScheduleModule.forRoot(),
    WinstonModule.forRoot(WinstonConfig)
  ],
  providers: [
    PrismaService,
    Logger,
    {
      provide: LOGGER_SERVICE,
      useExisting: Logger
    },
    // {
    //   provide: APP_GUARD,
    //   useClass: ThrottlerGuard
    // },
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
  ],
  exports: [ConfigModule, I18nModule, ThrottlerModule, ScheduleModule, PrismaService, LOGGER_SERVICE]
})
export class CoreModule {}
