import { Module } from '@nestjs/common'
import { OtpController } from './otp.controller'
import { OtpService } from './otp.service'
import { SharedModule } from 'src/shared/shared.module'

@Module({
  imports: [SharedModule],
  controllers: [OtpController],
  providers: [OtpService],
  exports: [OtpService]
})
export class OtpModule {}
