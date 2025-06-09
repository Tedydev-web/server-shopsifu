import { Global, Module } from '@nestjs/common'
import { JwtModule } from '@nestjs/jwt'

// Constants for Injection Tokens
import { OTP_SERVICE, SESSIONS_SERVICE, TWO_FACTOR_SERVICE } from '../../shared/constants/injection.tokens'
import { LOGIN_FINALIZER_SERVICE } from '../../shared/types/auth.types'

// Controllers
import { CoreController } from './controllers/core.controller'
import { OtpController } from './controllers/otp.controller'
import { PasswordController } from './controllers/password.controller'
import { SessionsController } from './controllers/session.controller'
import { SocialController } from './controllers/social.controller'
import { TwoFactorController } from './controllers/two-factor.controller'

// Repositories
import { DeviceRepository } from './repositories/device.repository'
import { RecoveryCodeRepository } from './repositories/recovery-code.repository'
import { SessionRepository } from './repositories/session.repository'
import { UserAuthRepository } from './repositories/user-auth.repository'

// Services
import { AuthVerificationService } from './services/auth-verification.service'
import { CoreService } from './services/core.service'
import { OtpService } from './services/otp.service'
import { PasswordService } from './services/password.service'
import { SessionsService } from './services/session.service'
import { SocialService } from './services/social.service'
import { TwoFactorService } from './services/two-factor.service'

@Global()
@Module({
  imports: [
    JwtModule.register({}) // Configure this properly with secret, signOptions, etc.
    // SharedModule, // Only if SharedModule is not global or AuthModule needs specific imports from it
  ],
  controllers: [
    CoreController,
    OtpController,
    PasswordController,
    SessionsController,
    SocialController,
    TwoFactorController
  ],
  providers: [
    // Repositories
    DeviceRepository,
    RecoveryCodeRepository,
    SessionRepository,
    UserAuthRepository,

    // Services
    AuthVerificationService,
    CoreService,
    OtpService,
    PasswordService,
    SessionsService,
    SocialService,
    TwoFactorService,
    // Custom providers for injection tokens
    {
      provide: OTP_SERVICE,
      useExisting: OtpService
    },
    {
      provide: SESSIONS_SERVICE,
      useClass: SessionsService // Note: useClass, not useExisting, as per original sessions.module
    },
    {
      provide: TWO_FACTOR_SERVICE,
      useClass: TwoFactorService // Note: useClass, not useExisting, as per original two-factor.module
    },
    {
      provide: LOGIN_FINALIZER_SERVICE,
      useExisting: CoreService
    }
    // RedisService, // Likely provided by SharedModule globally
  ],
  exports: [
    // Repositories
    DeviceRepository,
    RecoveryCodeRepository,
    SessionRepository,
    UserAuthRepository,

    // Services
    AuthVerificationService,
    CoreService,
    OtpService,
    OTP_SERVICE,
    PasswordService,
    SessionsService,
    SESSIONS_SERVICE,
    SocialService,
    TwoFactorService,
    TWO_FACTOR_SERVICE,
    LOGIN_FINALIZER_SERVICE
  ]
})
export class AuthModule {}
