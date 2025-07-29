import { Injectable, BadRequestException } from '@nestjs/common'
import { OrderStatus } from 'src/shared/constants/order.constant'
import { PaymentStatus } from 'src/shared/constants/payment.constant'
import { PrismaService } from 'src/shared/services/prisma.service'
import { OrderIncludeProductSKUSnapshotAndDiscountType } from '../models/shared-order.model'
import { PaymentProducer } from '../producers/payment.producer'

@Injectable()
export class SharedPaymentRepository {
  constructor(
    private readonly prismaService: PrismaService,
    private readonly paymentProducer: PaymentProducer
  ) {}

  /**
   * Validate và tìm payment với orders
   * @param paymentId Payment ID
   * @returns Payment với orders
   */
  async validateAndFindPayment(paymentId: string) {
    const payment = await this.prismaService.payment.findUnique({
      where: { id: paymentId },
      include: {
        orders: {
          include: {
            items: true,
            discounts: true
          }
        }
      }
    })

    if (!payment) {
      throw new BadRequestException(`Cannot find payment with id ${paymentId}`)
    }

    return payment
  }

  /**
   * Validate số tiền thanh toán
   * @param orders Orders
   * @param expectedAmount Số tiền mong đợi
   * @param actualAmount Số tiền thực tế
   */
  validatePaymentAmount(
    orders: OrderIncludeProductSKUSnapshotAndDiscountType[],
    expectedAmount: string,
    actualAmount: string | number
  ) {
    const totalPrice = this.getTotalPrice(orders)
    if (totalPrice !== actualAmount.toString()) {
      throw new BadRequestException(`Price not match, expected ${totalPrice} but got ${actualAmount}`)
    }
  }

  /**
   * Cập nhật trạng thái payment và orders khi thanh toán thành công
   * @param paymentId Payment ID
   * @param orders Orders
   */
  async updatePaymentAndOrdersOnSuccess(paymentId: string, orders: OrderIncludeProductSKUSnapshotAndDiscountType[]) {
    await Promise.all([
      this.prismaService.payment.update({
        where: { id: paymentId },
        data: { status: PaymentStatus.SUCCESS }
      }),
      this.prismaService.order.updateMany({
        where: {
          id: { in: orders.map((order) => order.id) }
        },
        data: { status: OrderStatus.PENDING_PICKUP }
      }),
      this.paymentProducer.removeJob(paymentId)
    ])
  }

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
