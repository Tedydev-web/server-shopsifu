import { Module } from '@nestjs/common'
import { SessionsController } from './session.controller'

@Module({
  imports: [],
  controllers: [SessionsController],
  providers: [],
  exports: []
})
export class SessionsModule {}
