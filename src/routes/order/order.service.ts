import { Injectable } from '@nestjs/common'
import { CreateOrderBodyType, GetOrderListQueryType } from 'src/routes/order/order.model'
import { OrderRepo } from 'src/routes/order/order.repo'

@Injectable()
export class OrderService {
  constructor(private readonly orderRepo: OrderRepo) {}

  async list(userId: string, query: GetOrderListQueryType) {
    return this.orderRepo.list(userId, query)
  }

  async create(userId: string, body: CreateOrderBodyType) {
    const result = await this.orderRepo.create(userId, body)
    return result
  }

  cancel(userId: string, orderId: string) {
    return this.orderRepo.cancel(userId, orderId)
  }

  detail(userId: string, orderId: string) {
    return this.orderRepo.detail(userId, orderId)
  }
}
