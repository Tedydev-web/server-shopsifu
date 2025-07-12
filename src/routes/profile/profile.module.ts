import { Module } from '@nestjs/common'
import { ProfileController } from './profile.controller'
import { ProfileService } from './profile.service'
import { SharedModule } from 'src/shared/shared.module'
import { HelperModule } from 'src/shared/helper/helper.module'

@Module({
	imports: [SharedModule, HelperModule],
	controllers: [ProfileController],
	providers: [ProfileService],
	exports: [ProfileService]
})
export class ProfileModule {}
