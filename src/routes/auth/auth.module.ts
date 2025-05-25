import { Global, Module } from '@nestjs/common'
import { JwtModule } from '@nestjs/jwt'
import { AuthService } from './auth.service'
import { AuthController } from './auth.controller'
import { RolesService } from 'src/routes/auth/roles.service'
import { GoogleService } from 'src/routes/auth/google.service'
import { AuditLogModule } from 'src/routes/audit-log/audit-log.module'
import { AuthenticationService } from './services/authentication.service'
import { TwoFactorAuthService } from './services/two-factor-auth.service'
import { OtpAuthService } from './services/otp-auth.service'
import { DeviceAuthService } from './services/device-auth.service'
import { PasswordAuthService } from './services/password-auth.service'
import { BaseAuthService } from './services/base-auth.service'
import { SharedModule } from 'src/shared/shared.module'
import { TokenService } from './providers/token.service'
import { EmailService } from './providers/email.service'
import { TwoFactorService } from './providers/2fa.service'
import { OtpService } from './providers/otp.service'
import { DeviceService } from './providers/device.service'
import { AuthRepository } from './auth.repo'
import { AccessTokenGuard } from './guards/access-token.guard'
import { TokenRefreshInterceptor } from './interceptors/token-refresh.interceptor'
import { SharedUserRepository } from './repositories/shared-user.repo'
import { APP_INTERCEPTOR } from '@nestjs/core'

const authProviders = [
  TokenService,
  EmailService,
  TwoFactorService,
  OtpService,
  DeviceService,
  AuthRepository,
  SharedUserRepository
]

@Global()
@Module({
  imports: [AuditLogModule, SharedModule, JwtModule.register({})],
  providers: [
    AuthService,
    RolesService,
    GoogleService,
    BaseAuthService,
    AuthenticationService,
    TwoFactorAuthService,
    OtpAuthService,
    DeviceAuthService,
    PasswordAuthService,
    ...authProviders,
    AccessTokenGuard,
    {
      provide: APP_INTERCEPTOR,
      useClass: TokenRefreshInterceptor
    }
  ],
  controllers: [AuthController],
  exports: [AuthService, ...authProviders, AccessTokenGuard]
})
export class AuthModule {}
