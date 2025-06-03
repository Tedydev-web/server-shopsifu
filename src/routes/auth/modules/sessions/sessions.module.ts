import { Module, forwardRef } from '@nestjs/common'
import { SessionsController } from './sessions.controller'
import { SessionsService } from './sessions.service'
import { SharedModule } from 'src/shared/shared.module'
import { OtpModule } from '../otp/otp.module'
import { CookieService } from '../../shared/cookie/cookie.service'
import { EmailService } from 'src/shared/services/email.service'
import { EMAIL_SERVICE } from 'src/shared/constants/injection.tokens'
import { DeviceRepository } from '../../repositories/device.repository'
import { SessionRepository } from '../../repositories/session.repository'
import { TokenService } from '../../shared/token/token.service'

@Module({
  imports: [SharedModule, forwardRef(() => OtpModule)],
  controllers: [SessionsController],
  providers: [
    SessionsService,
    SessionRepository,
    DeviceRepository,
    TokenService,
    {
      provide: EMAIL_SERVICE,
      useClass: EmailService
    },
    CookieService
  ],
  exports: [SessionsService]
})
export class SessionsModule {}
