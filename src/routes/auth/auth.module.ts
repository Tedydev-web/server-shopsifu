import { Module } from '@nestjs/common'

import { CoreModule } from './modules/core/core.module'
import { SessionsModule } from './modules/sessions/session.module'
import { OtpModule } from './modules/otp/otp.module'
import { SocialModule } from './modules/social/social.module'
import { TwoFactorModule } from './modules/two-factor/two-factor.module'
import { AuthSharedModule } from './shared/auth-shared.module'
import { AuthVerificationModule } from '../../shared/services/auth-verification.module'

@Module({
  imports: [
    AuthSharedModule,
    AuthVerificationModule,
    CoreModule,
    SessionsModule,
    OtpModule,
    SocialModule,
    TwoFactorModule
  ],
  providers: [],
  exports: [AuthSharedModule]
})
export class AuthModule {}
