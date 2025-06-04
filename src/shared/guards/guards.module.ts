import { Module } from '@nestjs/common'
import { APP_GUARD } from '@nestjs/core'
import { ThrottlerGuard, ThrottlerModule } from '@nestjs/throttler'
import { ConfigModule, ConfigService } from '@nestjs/config'
import { JwtModule, JwtService } from '@nestjs/jwt'

import { AuthenticationGuard } from './authentication.guard'
import { APIKeyGuard } from './api-key.guard'
import { RedisProviderModule } from '../providers/redis/redis.module'
import { TokenService } from 'src/shared/services/token.service'
import { JwtAuthGuard } from 'src/routes/auth/guards/jwt-auth.guard'
import { ApiKeyGuard } from 'src/routes/auth/guards/api-key.guard'
import { BasicAuthGuard } from 'src/routes/auth/guards/basic-auth.guard'
import { AccessTokenGuard } from 'src/routes/auth/guards/access-token.guard'
import { RolesGuard } from 'src/routes/auth/guards/roles.guard'
import { UserAuthRepository } from 'src/routes/auth/repositories/user-auth.repository'
import { HashingService } from '../services/hashing.service'
import { PrismaService } from '../services/prisma.service'

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
    TokenService,
    JwtService,
    JwtAuthGuard,
    ApiKeyGuard,
    BasicAuthGuard,
    AccessTokenGuard,
    RolesGuard,
    UserAuthRepository,
    HashingService,
    PrismaService,
    APIKeyGuard
  ],
  exports: [JwtAuthGuard, ApiKeyGuard, BasicAuthGuard, AccessTokenGuard, RolesGuard]
})
export class GuardsModule {}
