import { Module } from '@nestjs/common'
import { SessionsController } from './sessions.controller'
import { SessionsService } from './sessions.service'
import { PrismaService } from 'src/shared/services/prisma.service'
import { TokenService } from 'src/routes/auth/shared/token/token.service'
import { EmailService } from 'src/shared/services/email.service'
import { DeviceRepository } from 'src/routes/auth/repositories/device.repository'
import { SessionRepository } from 'src/routes/auth/repositories/session.repository'
import { ConfigService } from '@nestjs/config'
import { EMAIL_SERVICE, REDIS_SERVICE } from 'src/shared/constants/injection.tokens'
import { SharedModule } from 'src/shared/shared.module'
import { VerifyActionController } from './verify-action.controller'

@Module({
  imports: [SharedModule],
  controllers: [SessionsController, VerifyActionController],
  providers: [
    SessionsService,
    TokenService,
    PrismaService,
    DeviceRepository,
    SessionRepository,
    ConfigService,
    {
      provide: EMAIL_SERVICE,
      useClass: EmailService
    }
  ],
  exports: [SessionsService]
})
export class SessionsModule {}
