import { forwardRef, Module } from '@nestjs/common'
import { SessionsController } from './session.controller'
import { SessionsService } from './session.service'
import { AuthSharedModule } from '../../shared/auth-shared.module'
import { OtpModule } from '../otp/otp.module'
import { TwoFactorModule } from '../two-factor/two-factor.module'
import { AuthVerificationModule } from '../../../../shared/services/auth-verification.module'

@Module({
  imports: [
    forwardRef(() => AuthSharedModule),
    forwardRef(() => OtpModule),
    TwoFactorModule,
    forwardRef(() => AuthVerificationModule)
  ],
  controllers: [SessionsController],
  providers: [SessionsService],
  exports: [SessionsService]
})
export class SessionsModule {}
