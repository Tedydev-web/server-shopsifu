import { Module } from '@nestjs/common'
import { SepayController } from './sepay.controller'
import { SepayService } from './sepay.service'
import { SepayRepo } from 'src/routes/payment/sepay/sepay.repo'
import { BullModule } from '@nestjs/bullmq'
import { PAYMENT_QUEUE_NAME } from 'src/shared/constants/queue.constant'

@Module({
  imports: [
    BullModule.registerQueue({
      name: PAYMENT_QUEUE_NAME
    })
  ],
  providers: [SepayService, SepayRepo],
  controllers: [SepayController]
})
export class SepayModule {}
