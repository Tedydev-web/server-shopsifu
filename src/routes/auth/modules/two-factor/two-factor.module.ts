import { Module, forwardRef } from '@nestjs/common'
import { TwoFactorController } from './two-factor.controller'
import { TwoFactorService } from './two-factor.service'
import { SharedModule } from 'src/shared/shared.module'
import { SessionsModule } from '../sessions/sessions.module'
import { OtpModule } from '../otp/otp.module'
import { CoreModule } from '../core/core.module'

@Module({
  imports: [SharedModule, forwardRef(() => OtpModule), forwardRef(() => SessionsModule), CoreModule],
  controllers: [TwoFactorController],
  providers: [TwoFactorService],
  exports: [TwoFactorService]
})
export class TwoFactorModule {}
