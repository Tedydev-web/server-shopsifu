import { Module, forwardRef } from '@nestjs/common'
import { SocialController } from './social.controller'
import { SocialService } from './social.service'
import { SharedModule } from 'src/shared/shared.module'
import { OtpModule } from '../otp/otp.module'
import { AuthModule } from '../../auth.module'

@Module({
  imports: [SharedModule, forwardRef(() => OtpModule), forwardRef(() => AuthModule)],
  controllers: [SocialController],
  providers: [SocialService],
  exports: [SocialService]
})
export class SocialModule {}
