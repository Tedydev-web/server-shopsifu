import { forwardRef, Module } from '@nestjs/common'
import { SessionsController } from './sessions.controller'
import { SessionsService } from './sessions.service'
import { OtpModule } from '../otp/otp.module'
import { TwoFactorModule } from '../two-factor/two-factor.module'
import { SharedModule } from 'src/shared/shared.module'

@Module({
  imports: [forwardRef(() => OtpModule), TwoFactorModule, forwardRef(() => SharedModule)],
  controllers: [SessionsController],
  providers: [SessionsService],
  exports: [SessionsService]
})
export class SessionsModule {}
