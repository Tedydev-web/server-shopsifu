import { Global, Module } from '@nestjs/common'
import { CoreModule } from './modules/core/core.module'
import { SessionsModule } from './modules/sessions/session.module'
import { OtpModule } from './modules/otp/otp.module'
import { SocialModule } from './modules/social/social.module'
import { TwoFactorModule } from './modules/two-factor/two-factor.module'
import { PasswordModule } from './modules/password/password.module'
import { AuthVerificationService } from './services/auth-verification.service'

@Global()
@Module({
  imports: [CoreModule, SessionsModule, OtpModule, SocialModule, TwoFactorModule, PasswordModule],
  providers: [AuthVerificationService],
  exports: [
    AuthVerificationService,
    CoreModule,
    SessionsModule,
    OtpModule,
    SocialModule,
    TwoFactorModule,
    PasswordModule
  ]
})
export class AuthModule {}
