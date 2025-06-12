import { Module, forwardRef } from '@nestjs/common'
import { AuthModule } from 'src/routes/auth/auth.module'
import { RoleModule } from 'src/routes/role/role.module'
import { SharedModule } from 'src/shared/shared.module'
import { UserController } from './user.controller'
import { UserRepository } from './user.repository'
import { UserService } from './user.service'

@Module({
  imports: [SharedModule, forwardRef(() => AuthModule), RoleModule],
  controllers: [UserController],
  providers: [UserService, UserRepository],
  exports: [UserService, UserRepository]
})
export class UserModule {}
