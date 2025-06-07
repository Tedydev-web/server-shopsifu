import { forwardRef, Module } from '@nestjs/common'
import { OtpController } from './otp.controller'
import { OtpService } from './otp.service'
import { CoreModule } from '../core/core.module'
import { SessionsModule } from '../sessions/session.module'
import { OTP_SERVICE } from 'src/shared/constants/injection.tokens'
import { AuthVerificationModule } from '../../../../shared/services/auth-verification.module'

@Module({
  imports: [forwardRef(() => CoreModule), SessionsModule, forwardRef(() => AuthVerificationModule)],
  controllers: [OtpController],
  providers: [
    OtpService,
    {
      provide: OTP_SERVICE,
      useExisting: OtpService
    }
  ],
  exports: [OtpService, OTP_SERVICE]
})
export class OtpModule {}
