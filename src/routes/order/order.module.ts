import { Module } from '@nestjs/common'
import { OrderService } from './order.service'
import { OrderRepo } from './order.repo'
import { OrderController } from 'src/routes/order/order.controller'
import { BullModule } from '@nestjs/bullmq'

@Module({
  imports: [
    BullModule.registerQueue({
      name: 'payment'
    })
  ],
  providers: [OrderService, OrderRepo],
  controllers: [OrderController]
})
export class OrderModule {}
