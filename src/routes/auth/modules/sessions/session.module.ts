import { Module } from '@nestjs/common'
import { SharedModule } from 'src/shared/shared.module'
import { SessionsController } from './session.controller'
import { SessionsService } from './session.service'
import { SESSIONS_SERVICE } from 'src/shared/constants/injection.tokens'

@Module({
  imports: [SharedModule],
  controllers: [SessionsController],
  providers: [SessionsService, { provide: SESSIONS_SERVICE, useClass: SessionsService }],
  exports: [SessionsService, SESSIONS_SERVICE]
})
export class SessionsModule {}
