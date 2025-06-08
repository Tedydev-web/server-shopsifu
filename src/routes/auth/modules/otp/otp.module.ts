import { forwardRef, Module } from '@nestjs/common'
import { JwtModule } from '@nestjs/jwt'
import { OtpController } from './otp.controller'
import { OtpService } from './otp.service'
import { CoreModule } from '../core/core.module'
import { SessionsModule } from '../sessions/session.module'
import { OTP_SERVICE } from 'src/shared/constants/injection.tokens'

@Module({
  imports: [JwtModule, forwardRef(() => CoreModule), SessionsModule],
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
