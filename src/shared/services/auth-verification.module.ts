import { Module, forwardRef } from '@nestjs/common'
import { AuthVerificationService } from './auth-verification.service'
import { AuthSharedModule } from '../../routes/auth/shared/auth-shared.module'
import { OtpModule } from '../../routes/auth/modules/otp/otp.module'
import { TwoFactorModule } from '../../routes/auth/modules/two-factor/two-factor.module'
import { CoreModule } from '../../routes/auth/modules/core/core.module'
import { SessionsModule } from '../../routes/auth/modules/sessions/session.module'
import { SocialModule } from '../../routes/auth/modules/social/social.module'

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
