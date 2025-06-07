import { Module, forwardRef } from '@nestjs/common'
import { SocialController } from './social.controller'
import { SocialService } from './social.service'
import { AuthSharedModule } from '../../shared/auth-shared.module'
import { OtpModule } from '../otp/otp.module'
import { AuthVerificationModule } from '../../../../shared/services/auth-verification.module'
import { CoreModule } from '../core/core.module'

@Module({
  imports: [
    AuthSharedModule,
    forwardRef(() => OtpModule),
    forwardRef(() => AuthVerificationModule),
    forwardRef(() => CoreModule)
  ],
  controllers: [SocialController],
  providers: [SocialService],
  exports: [SocialService]
})
export class SocialModule {}
