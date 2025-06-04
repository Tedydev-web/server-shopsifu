import { Module, forwardRef } from '@nestjs/common'
import { TwoFactorController } from './two-factor.controller'
import { TwoFactorService } from './two-factor.service'
import { SharedModule } from 'src/shared/shared.module'
import { SessionsModule } from '../sessions/sessions.module'
import { UserAuthRepository, RecoveryCodeRepository, DeviceRepository } from 'src/shared/repositories/auth'
import { OtpModule } from '../otp/otp.module'

@Module({
  imports: [SharedModule, forwardRef(() => SessionsModule), forwardRef(() => OtpModule)],
  controllers: [TwoFactorController],
  providers: [TwoFactorService, UserAuthRepository, RecoveryCodeRepository, DeviceRepository],
  exports: [TwoFactorService]
})
export class TwoFactorModule {}
