import { forwardRef, Module } from '@nestjs/common'
import { OtpController } from './otp.controller'
import { OtpService } from './otp.service'
import { CoreModule } from '../core/core.module'
import { SessionsModule } from '../sessions/sessions.module'

@Module({
  imports: [forwardRef(() => CoreModule), forwardRef(() => SessionsModule)],
  controllers: [OtpController],
  providers: [OtpService],
  exports: [OtpService]
})
export class OtpModule {}
