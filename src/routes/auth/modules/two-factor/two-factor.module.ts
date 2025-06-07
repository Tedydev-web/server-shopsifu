import { Module, forwardRef } from '@nestjs/common'
import { TwoFactorController } from './two-factor.controller'
import { TwoFactorService } from './two-factor.service'
import { SessionsModule } from '../sessions/session.module'
import { OtpModule } from '../otp/otp.module'
import { CoreModule } from '../core/core.module'
import { AuthVerificationModule } from '../../../../shared/services/auth-verification.module'
import { TWO_FACTOR_SERVICE } from 'src/shared/constants/injection.tokens'

@Module({
  imports: [
    forwardRef(() => OtpModule),
    forwardRef(() => SessionsModule),
    forwardRef(() => CoreModule),
    forwardRef(() => AuthVerificationModule)
  ],
  controllers: [TwoFactorController],
  providers: [
    {
      provide: TWO_FACTOR_SERVICE,
      useClass: TwoFactorService
    }
  ],
  exports: [TWO_FACTOR_SERVICE]
})
export class TwoFactorModule {}
