import { Module } from '@nestjs/common'
import { BullModule } from '@nestjs/bullmq'
import { ShippingController } from './shipping-ghn.controller'
import { ShippingService } from './shipping-ghn.service'
import { ShippingRepo } from './shipping-ghn.repo'
import { SHIPPING_QUEUE_NAME } from 'src/shared/constants/queue.constant'

@Module({
  imports: [
    BullModule.registerQueue({
      name: SHIPPING_QUEUE_NAME
    })
  ],
  providers: [ShippingService, ShippingRepo],
  controllers: [ShippingController]
})
export class ShippingModule {}
