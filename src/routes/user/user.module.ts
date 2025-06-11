import { Module, forwardRef } from '@nestjs/common'

import { UserService } from './user.service'
import { UserRepository } from './user.repository'
import { SharedModule } from 'src/shared/shared.module'
import { AuthModule } from 'src/routes/auth/auth.module'
import { UserController } from './user.controller'

@Module({
  imports: [forwardRef(() => SharedModule), forwardRef(() => AuthModule)],
  controllers: [UserController],
  providers: [UserService, UserRepository],
  exports: [UserService, UserRepository]
})
export class UserModule {}
