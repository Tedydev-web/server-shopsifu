import { Module, forwardRef } from '@nestjs/common'
import { UserService } from './user.service'
import { UserController } from './user.controller'
import { UserRepository } from './user.repository'
import { RoleModule } from '../role/role.module'
import { SharedModule } from 'src/shared/shared.module'
import { AuthModule } from '../auth/auth.module'

@Module({
  imports: [forwardRef(() => SharedModule), forwardRef(() => AuthModule), RoleModule],
  controllers: [UserController],
  providers: [UserService, UserRepository],
  exports: [UserService, UserRepository]
})
export class UserModule {}
