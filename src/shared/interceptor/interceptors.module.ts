import { Module } from '@nestjs/common'
import { APP_INTERCEPTOR } from '@nestjs/core'
import { TransformInterceptor } from './transform.interceptor'
import { TokenRefreshInterceptor } from 'src/routes/auth/interceptors/token-refresh.interceptor'
import { ConfigModule, ConfigService } from '@nestjs/config'
import { JwtModule } from '@nestjs/jwt'
import { CookieService } from 'src/shared/services/cookie.service'
import { TokenService } from 'src/shared/services/token.service'
import { SharedModule } from '../shared.module'
import { RedisProviderModule } from '../providers/redis/redis.module'

/**
 * Module tập trung quản lý tất cả các interceptor trong ứng dụng
 */
@Module({
  imports: [
    ConfigModule,
    SharedModule,
    RedisProviderModule,
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: async (configService: ConfigService) => ({
        secret: configService.get('JWT_SECRET'),
        signOptions: {
          expiresIn: configService.get('JWT_ACCESS_EXPIRATION', '15m')
        }
      }),
      inject: [ConfigService]
    })
  ],
  providers: [
    {
      provide: APP_INTERCEPTOR,
      useClass: TransformInterceptor
    },
    {
      provide: APP_INTERCEPTOR,
      useClass: TokenRefreshInterceptor
    },
    CookieService,
    TokenService
  ],
  exports: []
})
export class InterceptorsModule {}
