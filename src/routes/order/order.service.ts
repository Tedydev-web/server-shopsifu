import { Injectable } from '@nestjs/common'
import { CreateOrderBodyType, GetOrderListQueryType, GetOrderListResType } from 'src/routes/order/order.model'
import { OrderProducer } from 'src/routes/order/order.producer'
import { OrderRepo } from 'src/routes/order/order.repo'

@Injectable()
export class OrderService {
  constructor(
    private readonly orderRepo: OrderRepo,
    private orderProducer: OrderProducer,
  ) {}

  async list(userId: number, query: GetOrderListQueryType) {
    return this.orderRepo.list(userId, query)
  }

  async create(userId: number, body: CreateOrderBodyType) {
    const result = await this.orderRepo.create(userId, body)
    await this.orderProducer.addCancelPaymentJob(result.paymentId)
    return {
      data: result.orders,
    }
  }

  cancel(userId: number, orderId: number) {
    return this.orderRepo.cancel(userId, orderId)
  }

  detail(userId: number, orderId: number) {
    return this.orderRepo.detail(userId, orderId)
  }
}
