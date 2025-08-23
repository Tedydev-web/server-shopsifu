import { Injectable } from '@nestjs/common'
import { PrismaService } from 'src/shared/services/prisma.service'

@Injectable()
export class SharedOrderRepository {
  constructor(private readonly prismaService: PrismaService) {}

  /**
   * Lấy thông tin order với shipping để Shipping module sử dụng
   */
  async getOrderWithShippingForGHN(orderId: string) {
    return this.prismaService.order.findUnique({
      where: {
        id: orderId,
        deletedAt: null
      },
      include: {
        items: true,
        discounts: true,
        shipping: true,
        shop: {
          include: {
            UserAddress: {
              where: { isDefault: true },
              include: { address: true }
            }
          }
        }
      }
    })
  }

  /**
   * Lấy order code GHN từ order ID
   * Sử dụng bởi Order module để trả về cho client
   */
  async getGHNOrderCode(orderId: string): Promise<string | null> {
    const orderShipping = await this.prismaService.orderShipping.findUnique({
      where: { orderId },
      select: { orderCode: true, status: true }
    })

    // Chỉ trả về orderCode nếu shipping đã được tạo thành công
    if (orderShipping?.status === 'CREATED' && orderShipping.orderCode) {
      return orderShipping.orderCode
    }

    return null
  }
}
