import { Module } from '@nestjs/common'
import { OrderService } from './order.service'
import { OrderRepo } from './order.repo'
import { OrderController } from 'src/routes/order/order.controller'
import { BullModule } from '@nestjs/bullmq'
import { PAYMENT_QUEUE_NAME } from 'src/shared/constants/queue.constant'
import { OrderProducer } from 'src/routes/order/order.producer'
import { DiscountModule } from 'src/routes/discount/discount.module'
import { SharedModule } from 'src/shared/shared.module'

@Module({
  imports: [
    BullModule.registerQueue({
      name: PAYMENT_QUEUE_NAME
    }),
    DiscountModule,
    SharedModule
  ],
  providers: [OrderService, OrderRepo, OrderProducer],
  controllers: [OrderController]
})
export class OrderModule {}
