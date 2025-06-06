import { forwardRef, Module } from '@nestjs/common'
import { OtpController } from './otp.controller'
import { OtpService } from './otp.service'
import { CoreModule } from '../core/core.module'
import { SessionsModule } from '../sessions/sessions.module'
import { OTP_SERVICE_TOKEN } from 'src/shared/constants/injection.tokens'

@Module({
  imports: [forwardRef(() => CoreModule), forwardRef(() => SessionsModule)],
  controllers: [OtpController],
  providers: [
    OtpService,
    {
      provide: OTP_SERVICE_TOKEN,
      useExisting: OtpService
    }
  ],
  exports: [OtpService, OTP_SERVICE_TOKEN]
})
export class OtpModule {}
