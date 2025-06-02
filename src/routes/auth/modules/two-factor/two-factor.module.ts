import { Module } from '@nestjs/common'
import { TwoFactorController } from './two-factor.controller'
import { TwoFactorService } from './two-factor.service'
import { SharedModule } from 'src/shared/shared.module'

@Module({
  imports: [SharedModule],
  controllers: [TwoFactorController],
  providers: [TwoFactorService],
  exports: [TwoFactorService]
})
export class TwoFactorModule {}
