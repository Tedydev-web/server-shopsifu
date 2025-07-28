import { Injectable } from '@nestjs/common'
import { OrderStatus } from 'src/shared/constants/order.constant'
import { PaymentStatus } from 'src/shared/constants/payment.constant'
import { PrismaService } from 'src/shared/services/prisma.service'
import { OrderIncludeProductSKUSnapshotAndDiscountType } from '../models/shared-order.model'

@Injectable()
export class SharedPaymentRepository {
  constructor(private readonly prismaService: PrismaService) {}

  async cancelPaymentAndOrder(paymentId: string) {
    const payment = await this.prismaService.payment.findUnique({
      where: {
        id: paymentId
      },
      include: {
        orders: {
          include: {
            items: true
          }
        }
      }
    })
    if (!payment) {
      throw Error('Payment not found')
    }
    const { orders } = payment
    const productSKUSnapshots = orders.map((order) => order.items).flat()
    await this.prismaService.$transaction(async (tx) => {
      const updateOrder$ = tx.order.updateMany({
        where: {
          id: {
            in: orders.map((order) => order.id)
          },
          status: OrderStatus.PENDING_PAYMENT,
          deletedAt: null
        },
        data: {
          status: OrderStatus.CANCELLED
        }
      })

      const updateSkus$ = Promise.all(
        productSKUSnapshots
          .filter((item) => item.skuId)
          .map((item) =>
            tx.sKU.update({
              where: {
                id: item.skuId as string
              },
              data: {
                stock: {
                  increment: item.quantity
                }
              }
            })
          )
      )

      const updatePayment$ = tx.payment.update({
        where: {
          id: paymentId
        },
        data: {
          status: PaymentStatus.FAILED
        }
      })
      return await Promise.all([updateOrder$, updateSkus$, updatePayment$])
    })
  }

  getTotalPrice(orders: OrderIncludeProductSKUSnapshotAndDiscountType[]): string {
    return orders
      .reduce((total, order) => {
        // Tính tổng tiền sản phẩm
        const productTotal = order.items.reduce((totalPrice: number, productSku: any) => {
          return totalPrice + productSku.skuPrice * productSku.quantity
        }, 0)

        // Tính tổng giảm giá từ DiscountSnapshot
        const discountTotal =
          order.discounts?.reduce((totalDiscount: number, discount: any) => {
            return totalDiscount + discount.discountAmount
          }, 0) || 0

        // Cộng vào tổng (đã trừ giảm giá)
        return total + (productTotal - discountTotal)
      }, 0)
      .toString()
  }
}
