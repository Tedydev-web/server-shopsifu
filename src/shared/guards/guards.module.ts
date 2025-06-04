import { Module } from '@nestjs/common'
import { APP_GUARD } from '@nestjs/core'
import { ThrottlerGuard, ThrottlerModule } from '@nestjs/throttler'
import { ConfigModule, ConfigService } from '@nestjs/config'
import { JwtModule, JwtService } from '@nestjs/jwt'

import { AuthenticationGuard } from './authentication.guard'
import { RedisProviderModule } from '../providers/redis/redis.module'
import { JwtAuthGuard } from './auth/jwt-auth.guard'
import { ApiKeyGuard } from './auth/api-key.guard'
import { BasicAuthGuard } from './auth/basic-auth.guard'
import { RolesGuard } from './auth/roles.guard'

/**
 * Module tập trung quản lý tất cả các guard trong ứng dụng
 */
@Module({
  imports: [
    ConfigModule,
    RedisProviderModule,
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: (configService: ConfigService) => ({
        secret: configService.get<string>('JWT_SECRET') || 'SECRET',
        signOptions: {
          expiresIn: configService.get<string>('JWT_ACCESS_EXPIRATION', '1h')
        }
      }),
      inject: [ConfigService]
    }),
    ThrottlerModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (config: ConfigService) => [
        {
          ttl: config.get('THROTTLE_TTL', 60000),
          limit: config.get('THROTTLE_LIMIT', 100)
        }
      ]
    })
  ],
  providers: [
    // Global guards
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard
    },
    {
      provide: APP_GUARD,
      useClass: AuthenticationGuard
    },

    // Các guard và dependency của chúng
    JwtService,
    JwtAuthGuard,
    ApiKeyGuard,
    BasicAuthGuard,
    RolesGuard
  ],
  exports: [JwtAuthGuard, ApiKeyGuard, BasicAuthGuard, RolesGuard]
})
export class GuardsModule {}
