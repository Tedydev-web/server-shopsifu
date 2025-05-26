import { Global, Module } from '@nestjs/common'
import { JwtModule } from '@nestjs/jwt'
import { PassportModule } from '@nestjs/passport'
import { AuthController } from 'src/routes/auth/auth.controller'
import { AuthService } from 'src/routes/auth/auth.service'
import { GoogleService } from 'src/routes/auth/google.service'
import { HashingService } from 'src/shared/services/hashing.service'
import { PrismaService } from 'src/shared/services/prisma.service'
import { AuthRepository } from 'src/routes/auth/auth.repo'
import { SharedUserRepository } from './repositories/shared-user.repo'
import { RolesService } from './roles.service'
import { EmailService } from './providers/email.service'
import { TokenService } from './providers/token.service'
import { TwoFactorService } from './providers/2fa.service'
import { AuditLogService } from '../audit-log/audit-log.service'
import { AuditLogRepository } from '../audit-log/audit-log.repo'
import { OtpService } from './providers/otp.service'
import { DeviceService } from './providers/device.service'
import { AuthenticationService } from './services/authentication.service'
import { TwoFactorAuthService } from './services/two-factor-auth.service'
import { OtpAuthService } from './services/otp-auth.service'
import { PasswordAuthService } from './services/password-auth.service'
import { SessionManagementService } from './services/session-management.service'
import { AuditLogModule } from '../audit-log/audit-log.module'

@Global()
@Module({
  imports: [PassportModule, JwtModule.register({}), AuditLogModule],
  controllers: [AuthController],
  providers: [
    AuthService,
    GoogleService,
    AuthRepository,
    SharedUserRepository,
    RolesService,
    EmailService,
    TokenService,
    TwoFactorService,
    OtpService,
    DeviceService,
    AuthenticationService,
    TwoFactorAuthService,
    OtpAuthService,
    PasswordAuthService,
    SessionManagementService
  ],
  exports: [
    AuthService,
    TokenService,
    DeviceService,
    AuthenticationService,
    OtpService,
    RolesService,
    TwoFactorService,
    PasswordAuthService,
    TwoFactorAuthService,
    OtpAuthService,
    SessionManagementService,
    GoogleService,
    SharedUserRepository
  ]
})
export class AuthModule {}
