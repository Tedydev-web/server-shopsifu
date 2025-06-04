import { Module } from '@nestjs/common'

import { CoreModule } from './modules/core/core.module'
import { SessionsModule } from './modules/sessions/sessions.module'
import { OtpModule } from './modules/otp/otp.module'
import { SocialModule } from './modules/social/social.module'
import { TwoFactorModule } from './modules/two-factor/two-factor.module'

@Module({
  imports: [CoreModule, SessionsModule, OtpModule, SocialModule, TwoFactorModule],
  providers: [],
  exports: []
})
export class AuthModule {}
