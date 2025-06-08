import { Module, forwardRef } from '@nestjs/common'
import { PasswordController } from './password.controller'
import { PasswordService } from './password.service'
import { SessionsModule } from '../sessions/session.module'

@Module({
  imports: [forwardRef(() => SessionsModule)],
  controllers: [PasswordController],
  providers: [PasswordService],
  exports: [PasswordService]
})
export class PasswordModule {}
