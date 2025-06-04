import { Module, forwardRef } from '@nestjs/common'
import { CoreController } from './core.controller'
import { CoreService } from './core.service'
import { SharedModule } from 'src/shared/shared.module'
import { DeviceRepository, SessionRepository, UserAuthRepository } from 'src/shared/repositories/auth'
import { OtpModule } from '../otp/otp.module'

@Module({
  imports: [SharedModule, forwardRef(() => OtpModule)],
  controllers: [CoreController],
  providers: [CoreService, UserAuthRepository, DeviceRepository, SessionRepository],
  exports: [CoreService]
})
export class CoreModule {}
