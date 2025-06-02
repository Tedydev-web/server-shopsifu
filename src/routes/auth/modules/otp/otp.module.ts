import { Module } from '@nestjs/common'
import { OtpController } from './otp.controller'
import { OtpService } from './otp.service'
import { SharedModule } from 'src/shared/shared.module'
import { CoreService } from '../core/core.service'

@Module({
  imports: [SharedModule],
  controllers: [OtpController],
  providers: [OtpService, CoreService],
  exports: [OtpService]
})
export class OtpModule {}
