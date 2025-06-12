import { Global, Module, forwardRef } from '@nestjs/common'
import { JwtModule } from '@nestjs/jwt'

// Constants for Injection Tokens
import {
  DEVICE_SERVICE,
  OTP_SERVICE,
  SESSIONS_SERVICE,
  TWO_FACTOR_SERVICE
} from '../../shared/constants/injection.tokens'
import { LOGIN_FINALIZER_SERVICE } from './auth.types'

// Controllers
import { CoreController } from './controllers/core.controller'
import { OtpController } from './controllers/otp.controller'
import { PasswordController } from './controllers/password.controller'
import { SessionsController } from './controllers/session.controller'
import { SocialController } from './controllers/social.controller'
import { TwoFactorController } from './controllers/two-factor.controller'

// Guards
import { AuthenticationGuard } from './guards/authentication.guard'
import { BasicAuthGuard } from './guards/basic-auth.guard'
import { JwtAuthGuard } from './guards/jwt-auth.guard'
import { PermissionGuard } from 'src/shared/guards/permission.guard'

// Repositories
import { DeviceRepository } from '../../shared/repositories/device.repository'
import { RecoveryCodeRepository } from './repositories/recovery-code.repository'
import { SessionRepository } from './repositories/session.repository'

// Services
import { AuthVerificationService } from './services/auth-verification.service'
import { CoreService } from './services/core.service'
import { OtpService } from './services/otp.service'
import { PasswordService } from './services/password.service'
import { SessionsService } from './services/session.service'
import { SocialService } from './services/social.service'
import { TwoFactorService } from './services/two-factor.service'
import { DeviceService } from './services/device.service'
import { UserActivityService } from './services/user-activity.service'
import { UserModule } from 'src/routes/user/user.module'
import { ProfileModule } from 'src/routes/profile/profile.module'
import { RoleModule } from 'src/routes/role/role.module'

@Global()
@Module({
  imports: [
    JwtModule.register({}), // Configure this properly with secret, signOptions, etc.
    // SharedModule, // Only if SharedModule is not global or AuthModule needs specific imports from it
    forwardRef(() => UserModule),
    forwardRef(() => ProfileModule),
    RoleModule
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
    // Guards
    AuthenticationGuard,
    BasicAuthGuard,
    JwtAuthGuard,
    PermissionGuard,

    // Repositories
    DeviceRepository,
    RecoveryCodeRepository,
    SessionRepository,

    // Services
    AuthVerificationService,
    CoreService,
    OtpService,
    PasswordService,
    SessionsService,
    SocialService,
    TwoFactorService,
    DeviceService,
    UserActivityService,

    // Custom providers for injection tokens
    {
      provide: OTP_SERVICE,
      useExisting: OtpService
    },
    {
      provide: SESSIONS_SERVICE,
      useClass: SessionsService
    },
    {
      provide: TWO_FACTOR_SERVICE,
      useClass: TwoFactorService
    },
    {
      provide: DEVICE_SERVICE,
      useClass: DeviceService
    },
    {
      provide: LOGIN_FINALIZER_SERVICE,
      useExisting: CoreService
    }
  ],
  exports: [
    // Guards
    AuthenticationGuard,
    BasicAuthGuard,
    JwtAuthGuard,
    PermissionGuard,

    // Repositories
    DeviceRepository,
    RecoveryCodeRepository,
    SessionRepository,

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
    DeviceService,
    DEVICE_SERVICE,
    UserActivityService,
    LOGIN_FINALIZER_SERVICE
  ]
})
export class AuthModule {}
