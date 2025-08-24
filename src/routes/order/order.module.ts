import { Module } from '@nestjs/common'
import { OrderService } from './order.service'
import { OrderRepo } from './order.repo'
import { OrderController } from 'src/routes/order/order.controller'
import { ManageOrderController } from './manage-order/manage-order.controller'
import { ManageOrderService } from './manage-order/manage-order.service'
import { BullModule } from '@nestjs/bullmq'
import { PAYMENT_QUEUE_NAME } from 'src/shared/constants/queue.constant'
import { OrderProducer } from 'src/shared/queue/producer/order.producer'

@Module({
  imports: [
    BullModule.registerQueue({
      name: PAYMENT_QUEUE_NAME
    })
  ],
  providers: [OrderService, ManageOrderService, OrderRepo, OrderProducer],
  controllers: [OrderController, ManageOrderController]
})
export class OrderModule {}
