import { Module, forwardRef } from '@nestjs/common'
import { TwoFactorController } from './two-factor.controller'
import { TwoFactorService } from './two-factor.service'
import { SessionsModule } from '../sessions/sessions.module'
import { OtpModule } from '../otp/otp.module'
import { CoreModule } from '../core/core.module'
import { AuthVerificationModule } from '../../services/auth-verification.module'

@Module({
  imports: [
    forwardRef(() => OtpModule),
    forwardRef(() => SessionsModule),
    forwardRef(() => CoreModule),
    forwardRef(() => AuthVerificationModule)
  ],
  controllers: [TwoFactorController],
  providers: [TwoFactorService],
  exports: [TwoFactorService]
})
export class TwoFactorModule {}
