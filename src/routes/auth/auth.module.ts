import { Module } from '@nestjs/common'

import { CoreModule } from './modules/core/core.module'
import { SessionsModule } from './modules/sessions/session.module'
import { OtpModule } from './modules/otp/otp.module'
import { SocialModule } from './modules/social/social.module'
import { TwoFactorModule } from './modules/two-factor/two-factor.module'
import { PasswordModule } from './modules/password/password.module'

@Module({
  imports: [CoreModule, SessionsModule, OtpModule, SocialModule, TwoFactorModule, PasswordModule],
  providers: [],
  exports: []
})
export class AuthModule {}
