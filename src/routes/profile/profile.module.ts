import { Module } from '@nestjs/common'
import { ProfileService } from './profile.service'
import { ProfileController } from './profile.controller'
import { AuthSharedModule } from '../auth/shared/auth-shared.module'

@Module({
  imports: [AuthSharedModule],
  providers: [ProfileService],
  controllers: [ProfileController]
})
export class ProfileModule {}
