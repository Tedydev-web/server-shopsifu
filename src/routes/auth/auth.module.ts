import { Module, DynamicModule, Global } from '@nestjs/common'
import { PassportModule } from '@nestjs/passport'
import { CoreModule } from './modules/core/core.module'
import { OtpModule } from './modules/otp/otp.module'
import { TwoFactorModule } from './modules/two-factor/two-factor.module'
import { SessionsModule } from './modules/sessions/sessions.module'
import { SocialModule } from './modules/social/social.module'
import { CoreService } from './modules/core/core.service'
import { OtpService } from './modules/otp/otp.service'
import { SessionsService } from './modules/sessions/sessions.service'
import { SocialService } from './modules/social/social.service'
import { TwoFactorService } from './modules/two-factor/two-factor.service'
import { JwtAuthGuard } from './guards/jwt-auth.guard'
import { BasicAuthGuard } from './guards/basic-auth.guard'
import { ApiKeyGuard } from './guards/api-key.guard'
import { AccessTokenGuard } from './guards/access-token.guard'
import { UserAuthRepository } from './repositories/user-auth.repository'
import { DeviceRepository } from './repositories/device.repository'
import { RecoveryCodeRepository } from './repositories/recovery-code.repository'
import { SessionRepository } from './repositories/session.repository'
import { USER_AUTH_SERVICE, OTP_SERVICE, SESSION_SERVICE, DEVICE_SERVICE } from 'src/shared/constants/injection.tokens'
import { DeviceService } from './services/device.service'
import { UserActivityService } from './services/user-activity.service'

@Global()
@Module({
  imports: [
    PassportModule.register({ defaultStrategy: 'jwt' }),
    CoreModule,
    OtpModule,
    TwoFactorModule,
    SessionsModule,
    SocialModule
  ],
  providers: [
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
    CoreService,
    OtpService,
    SessionsService,
    SocialService,
    TwoFactorService,
    JwtAuthGuard,
    BasicAuthGuard,
    ApiKeyGuard,
    AccessTokenGuard,
    UserAuthRepository,
    DeviceRepository,
    RecoveryCodeRepository,
    SessionRepository,
    DeviceService,
    UserActivityService
  ],
  exports: [
    PassportModule,
    USER_AUTH_SERVICE,
    OTP_SERVICE,
    SESSION_SERVICE,
    DEVICE_SERVICE,
    CoreService,
    OtpService,
    SessionsService,
    SocialService,
    TwoFactorService,
    JwtAuthGuard,
    BasicAuthGuard,
    ApiKeyGuard,
    AccessTokenGuard,
    UserAuthRepository,
    DeviceRepository,
    RecoveryCodeRepository,
    SessionRepository,
    DeviceService,
    UserActivityService
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
