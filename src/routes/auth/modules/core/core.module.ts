import { Module, forwardRef } from '@nestjs/common'
import { CoreController } from './core.controller'
import { CoreService } from './core.service'
import { OtpModule } from '../otp/otp.module'
import { SessionsModule } from '../sessions/session.module'
import { AuthVerificationModule } from '../../../../shared/services/auth-verification.module'

@Module({
  imports: [OtpModule, forwardRef(() => SessionsModule), forwardRef(() => AuthVerificationModule)],
  controllers: [CoreController],
  providers: [CoreService],
  exports: [CoreService]
})
export class CoreModule {}
