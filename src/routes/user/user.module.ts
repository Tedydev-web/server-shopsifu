import { Module } from '@nestjs/common'
import { UserController } from 'src/routes/user/user.controller'
import { UserRepo } from 'src/routes/user/user.repo'
import { UserService } from 'src/routes/user/user.service'
import { PaginationService } from 'src/shared/services/pagination.service'

@Module({
  providers: [UserService, UserRepo, PaginationService],
  controllers: [UserController],
})
export class UserModule {}
