import { Module } from '@nestjs/common'
import { CoreController } from './core.controller'
import { CoreService } from './core.service'
import { SharedModule } from 'src/shared/shared.module'

@Module({
  imports: [SharedModule],
  controllers: [CoreController],
  providers: [CoreService],
  exports: [CoreService]
})
export class CoreModule {}
