import { Module, DynamicModule, Global } from '@nestjs/common'
import { JwtModule } from '@nestjs/jwt'
import { PassportModule } from '@nestjs/passport'
import { ConfigModule, ConfigService } from '@nestjs/config'
import { CoreModule } from './modules/core/core.module'
import { OtpModule } from './modules/otp/otp.module'
import { TwoFactorModule } from './modules/two-factor/two-factor.module'
import { SessionsModule } from './modules/sessions/sessions.module'
import { SocialModule } from './modules/social/social.module'
import { CookieService } from './shared/cookie/cookie.service'
import { TokenService } from './shared/token/token.service'
import { CoreService } from './modules/core/core.service'
import { OtpService } from './modules/otp/otp.service'
import { SessionsService } from './modules/sessions/sessions.service'
import { SocialService } from './modules/social/social.service'
import { TwoFactorService } from './modules/two-factor/two-factor.service'
import { HashingService } from 'src/shared/services/hashing.service'
import { EmailService } from 'src/shared/services/email.service'
import { JwtAuthGuard } from './guards/jwt-auth.guard'
import { BasicAuthGuard } from './guards/basic-auth.guard'
import { ApiKeyGuard } from './guards/api-key.guard'
import { AccessTokenGuard } from './guards/access-token.guard'
import { UserAuthRepository } from './repositories/user-auth.repository'
import { DeviceRepository } from './repositories/device.repository'
import { RecoveryCodeRepository } from './repositories/recovery-code.repository'
import { SessionRepository } from './repositories/session.repository'
import { RedisProviderModule } from 'src/shared/providers/redis/redis.module'
import {
  COOKIE_SERVICE,
  TOKEN_SERVICE,
  USER_AUTH_SERVICE,
  OTP_SERVICE,
  SESSION_SERVICE,
  DEVICE_SERVICE,
  HASHING_SERVICE,
  REDIS_SERVICE,
  REDIS_CLIENT,
  EMAIL_SERVICE
} from 'src/shared/constants/injection.tokens'

@Global()
@Module({
  imports: [
    RedisProviderModule.register({
      connectionOptions: {
        host: 'localhost',
        port: 6379
      }
    }),
    PassportModule.register({ defaultStrategy: 'jwt' }),
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        secret: configService.get('ACCESS_TOKEN_SECRET'),
        signOptions: {
          expiresIn: configService.get('ACCESS_TOKEN_EXPIRES_IN', '15m')
        }
      })
    }),
    CoreModule,
    OtpModule,
    TwoFactorModule,
    SessionsModule,
    SocialModule
  ],
  providers: [
    // Providers với tokens
    {
      provide: COOKIE_SERVICE,
      useClass: CookieService
    },
    {
      provide: TOKEN_SERVICE,
      useClass: TokenService
    },
    {
      provide: USER_AUTH_SERVICE,
      useClass: CoreService
    },
    {
      provide: OTP_SERVICE,
      useClass: OtpService
    },
    {
      provide: SESSION_SERVICE,
      useClass: SessionsService
    },
    {
      provide: DEVICE_SERVICE,
      useClass: DeviceRepository
    },
    {
      provide: HASHING_SERVICE,
      useClass: HashingService
    },
    {
      provide: EMAIL_SERVICE,
      useClass: EmailService
    },
    // Đăng ký các service trực tiếp
    CookieService,
    TokenService,
    CoreService,
    OtpService,
    SessionsService,
    SocialService,
    TwoFactorService,
    EmailService,
    // Guards
    JwtAuthGuard,
    BasicAuthGuard,
    ApiKeyGuard,
    AccessTokenGuard,
    // Repositories
    UserAuthRepository,
    DeviceRepository,
    RecoveryCodeRepository,
    SessionRepository,
    // Services
    HashingService
  ],
  exports: [
    // Modules
    PassportModule,
    JwtModule,
    RedisProviderModule,
    // Tokens
    COOKIE_SERVICE,
    TOKEN_SERVICE,
    USER_AUTH_SERVICE,
    OTP_SERVICE,
    SESSION_SERVICE,
    DEVICE_SERVICE,
    HASHING_SERVICE,
    EMAIL_SERVICE,
    // Services
    CookieService,
    TokenService,
    CoreService,
    OtpService,
    SessionsService,
    SocialService,
    TwoFactorService,
    EmailService,
    // Guards
    JwtAuthGuard,
    BasicAuthGuard,
    ApiKeyGuard,
    AccessTokenGuard,
    // Repositories
    UserAuthRepository,
    DeviceRepository,
    RecoveryCodeRepository,
    SessionRepository,
    // Other services
    HashingService
  ]
})
export class AuthModule {
  /**
   * Đăng ký module với các tùy chọn
   */
  static register(options?: { isGlobal?: boolean }): DynamicModule {
    return {
      module: AuthModule,
      global: options?.isGlobal || true
    }
  }
}
