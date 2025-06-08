import { Module, forwardRef } from '@nestjs/common'
import { SocialController } from './social.controller'
import { SocialService } from './social.service'
import { OtpModule } from '../otp/otp.module'
import { CoreModule } from '../core/core.module'

@Module({
  imports: [forwardRef(() => OtpModule), forwardRef(() => CoreModule)],
  controllers: [SocialController],
  providers: [SocialService],
  exports: [SocialService]
})
export class SocialModule {}
