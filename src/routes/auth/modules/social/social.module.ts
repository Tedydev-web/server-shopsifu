import { Module, forwardRef } from '@nestjs/common'
import { SocialController } from './social.controller'
import { SocialService } from './social.service'
import { AuthSharedModule } from '../../shared/auth-shared.module'
import { OtpModule } from '../otp/otp.module'

@Module({
  imports: [AuthSharedModule, forwardRef(() => OtpModule)],
  controllers: [SocialController],
  providers: [SocialService],
  exports: [SocialService]
})
export class SocialModule {}
