import { forwardRef, Module } from '@nestjs/common'
import { SessionsController } from './sessions.controller'
import { SessionsService } from './sessions.service'
import { AuthSharedModule } from '../../shared/auth-shared.module'
import { OtpModule } from '../otp/otp.module'
import { TwoFactorModule } from '../two-factor/two-factor.module'

@Module({
  imports: [forwardRef(() => AuthSharedModule), forwardRef(() => OtpModule), TwoFactorModule],
  controllers: [SessionsController],
  providers: [SessionsService],
  exports: [SessionsService]
})
export class SessionsModule {}
