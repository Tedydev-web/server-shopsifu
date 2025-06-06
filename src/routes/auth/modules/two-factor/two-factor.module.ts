import { Module, forwardRef } from '@nestjs/common'
import { TwoFactorController } from './two-factor.controller'
import { TwoFactorService } from './two-factor.service'
import { SessionsModule } from '../sessions/sessions.module'
import { OtpModule } from '../otp/otp.module'
import { CoreModule } from '../core/core.module'

@Module({
  imports: [forwardRef(() => OtpModule), forwardRef(() => SessionsModule), forwardRef(() => CoreModule)],
  controllers: [TwoFactorController],
  providers: [TwoFactorService],
  exports: [TwoFactorService]
})
export class TwoFactorModule {}
