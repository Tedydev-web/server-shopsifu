import { Module } from '@nestjs/common'
import { SocialController } from './social.controller'
import { SocialService } from './social.service'
import { OtpModule } from '../otp/otp.module'
import { UserAuthRepository } from '../../repositories/user-auth.repository'
import { DeviceRepository } from '../../repositories/device.repository'
import { SessionRepository } from '../../repositories/session.repository'
import { EMAIL_SERVICE } from 'src/shared/constants/injection.tokens'
import { EmailService } from 'src/shared/services/email.service'

@Module({
  imports: [OtpModule],
  controllers: [SocialController],
  providers: [
    SocialService,
    UserAuthRepository,
    DeviceRepository,
    SessionRepository,
    {
      provide: EMAIL_SERVICE,
      useClass: EmailService
    }
  ],
  exports: [SocialService]
})
export class SocialModule {}
