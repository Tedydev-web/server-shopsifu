import { Module } from '@nestjs/common'
import { OrderService } from './order.service'
import { OrderRepo } from './order.repo'
import { OrderController } from 'src/routes/order/order.controller'
import { SharedModule } from 'src/shared/shared.module'

@Module({
  imports: [SharedModule],
  providers: [OrderService, OrderRepo],
  controllers: [OrderController],
})
export class OrderModule {}
