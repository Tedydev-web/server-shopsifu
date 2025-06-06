import { Module, forwardRef } from '@nestjs/common'
import { AuthVerificationService } from './auth-verification.service'
import { AuthSharedModule } from '../shared/auth-shared.module'
import { OtpModule } from '../modules/otp/otp.module'
import { TwoFactorModule } from '../modules/two-factor/two-factor.module'
import { CoreModule } from '../modules/core/core.module'
import { SessionsModule } from '../modules/sessions/sessions.module'
import { SocialModule } from '../modules/social/social.module'

@Module({
  imports: [
    AuthSharedModule,
    forwardRef(() => OtpModule),
    forwardRef(() => TwoFactorModule),
    forwardRef(() => CoreModule),
    forwardRef(() => SessionsModule),
    forwardRef(() => SocialModule)
  ],
  providers: [AuthVerificationService],
  exports: [AuthVerificationService]
})
export class AuthVerificationModule {}
