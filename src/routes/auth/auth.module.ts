import { Global, Module } from '@nestjs/common'
import { JwtModule } from '@nestjs/jwt'
import { PassportModule } from '@nestjs/passport'
import { AuthController } from 'src/routes/auth/auth.controller'
import { GoogleService } from 'src/routes/auth/google.service'
import { AuthRepository } from 'src/routes/auth/auth.repo'
import { RolesService } from './roles.service'
import { EmailService } from './providers/email.service'
import { TokenService } from './providers/token.service'
import { TwoFactorService } from './providers/2fa.service'
import { OtpService } from './providers/otp.service'
import { DeviceService } from './providers/device.service'
import { AuthenticationService } from './services/authentication.service'
import { TwoFactorAuthService } from './services/two-factor-auth.service'
import { PasswordAuthService } from './services/password-auth.service'
import { SessionManagementService } from './services/session-management.service'
import { AuditLogModule } from '../audit-log/audit-log.module'
import { PasswordReverificationGuard } from './guards/password-reverification.guard'
import { SessionFinalizationService } from './services/session-finalization.service'
import { SltHelperService } from './services/slt-helper.service'
import { UserRepository } from './repositories/shared-user.repo'

@Global()
@Module({
  imports: [PassportModule, JwtModule.register({}), AuditLogModule],
  controllers: [AuthController],
  providers: [
    GoogleService,
    AuthRepository,
    UserRepository,
    RolesService,
    EmailService,
    TokenService,
    TwoFactorService,
    OtpService,
    DeviceService,
    AuthenticationService,
    TwoFactorAuthService,
    PasswordAuthService,
    SessionManagementService,
    PasswordReverificationGuard,
    SessionFinalizationService,
    SltHelperService
  ],
  exports: [
    TokenService,
    DeviceService,
    AuthenticationService,
    OtpService,
    RolesService,
    TwoFactorService,
    PasswordAuthService,
    TwoFactorAuthService,
    SessionManagementService,
    GoogleService,
    SessionFinalizationService,
    SltHelperService,
    UserRepository
  ]
})
export class AuthModule {}
