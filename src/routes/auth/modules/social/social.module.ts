import { Module } from '@nestjs/common'
import { SocialController } from './social.controller'
import { SocialService } from './social.service'
import { SharedModule } from 'src/shared/shared.module'

@Module({
  imports: [SharedModule],
  controllers: [SocialController],
  providers: [SocialService],
  exports: [SocialService]
})
export class SocialModule {}
