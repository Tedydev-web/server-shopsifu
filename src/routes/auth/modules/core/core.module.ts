import { Module, forwardRef } from '@nestjs/common'
import { CoreController } from './core.controller'
import { CoreService } from './core.service'
import { OtpModule } from '../otp/otp.module'

@Module({
  imports: [forwardRef(() => OtpModule)],
  controllers: [CoreController],
  providers: [CoreService],
  exports: [CoreService]
})
export class CoreModule {}
