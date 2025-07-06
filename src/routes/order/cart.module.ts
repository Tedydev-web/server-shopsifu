import { Module } from '@nestjs/common'
import { OrderService } from './order.service'
import { OrderRepo } from './order.repo'
import { OrderController } from 'src/routes/order/order.controller'

@Module({
  providers: [OrderService, OrderRepo],
  controllers: [OrderController],
})
export class OrderModule {}
