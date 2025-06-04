import { Module, forwardRef } from '@nestjs/common'
import { CoreController } from './core.controller'
import { CoreService } from './core.service'
import { SharedModule } from 'src/shared/shared.module'
import { OtpModule } from '../otp/otp.module'

@Module({
  imports: [SharedModule, forwardRef(() => OtpModule)],
  controllers: [CoreController],
  providers: [CoreService],
  exports: [CoreService]
})
export class CoreModule {}
