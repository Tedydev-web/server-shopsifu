import { Module, forwardRef } from '@nestjs/common'
import { UserController } from './user.controller'
import { UserService } from './user.service'
import { UserRepository } from './user.repository'
import { SharedModule } from 'src/shared/shared.module'
import { CanCreateUserPolicy, CanDeleteUserPolicy, CanReadUserPolicy, CanUpdateUserPolicy } from './user.policies'

@Module({
  imports: [forwardRef(() => SharedModule)],
  controllers: [UserController],
  providers: [
    UserService,
    UserRepository,
    ...CanCreateUserPolicy,
    ...CanDeleteUserPolicy,
    ...CanReadUserPolicy,
    ...CanUpdateUserPolicy
  ],
  exports: [UserService, UserRepository]
})
export class UserModule {}
