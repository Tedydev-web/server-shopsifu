import { Injectable } from '@nestjs/common'
import { CreateOrderBodyType, GetOrderListQueryType, CalculateOrderBodyType } from 'src/routes/order/order.model'
import { OrderRepo } from 'src/routes/order/order.repo'
import { I18nService } from 'nestjs-i18n'
import { I18nTranslations } from 'src/shared/languages/generated/i18n.generated'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'
import { PrismaService } from 'src/shared/services/prisma.service'
import { calculateDiscountAmount } from 'src/shared/helpers'
import { DiscountNotFoundException, DiscountUsageLimitExceededException } from 'src/routes/discount/discount.error'
import { DiscountStatus } from 'src/shared/constants/discount.constant'

@Injectable()
export class OrderService {
  constructor(
    private readonly orderRepo: OrderRepo,
    private readonly i18n: I18nService<I18nTranslations>,
    private readonly prismaService: PrismaService
  ) {}

  async list(user: AccessTokenPayload, query: GetOrderListQueryType) {
    const data = await this.orderRepo.list(user.userId, query)
    return {
      message: this.i18n.t('order.order.success.GET_SUCCESS'),
      data: data.data,
      metadata: data.metadata
    }
  }

  async create(user: AccessTokenPayload, body: CreateOrderBodyType) {
    for (const shop of body) {
      if (shop.discountCodes && Array.isArray(shop.discountCodes)) {
        for (const discountCode of shop.discountCodes) {
          const discount = await this.prismaService.discount.findUnique({ where: { code: discountCode } })
          if (!discount) throw DiscountNotFoundException
          // Kiểm tra maxUsesPerUser
          if (discount.maxUsesPerUser && discount.maxUsesPerUser > 0) {
            const usedCount = await this.prismaService.discountSnapshot.count({
              where: { discountId: discount.id, order: { userId: user.userId } }
            })
            if (usedCount >= discount.maxUsesPerUser) throw DiscountUsageLimitExceededException
          }
        }
      }
    }
    const result = await this.orderRepo.create(user.userId, body)
    return {
      message: this.i18n.t('order.order.success.CREATE_SUCCESS'),
      data: result
    }
  }

  async cancel(user: AccessTokenPayload, orderId: string) {
    const result = await this.orderRepo.cancel(user.userId, orderId)
    return {
      message: this.i18n.t('order.order.success.CANCEL_SUCCESS'),
      data: result.data
    }
  }

  async detail(user: AccessTokenPayload, orderId: string) {
    const result = await this.orderRepo.detail(user.userId, orderId)
    return {
      message: this.i18n.t('order.order.success.GET_DETAIL_SUCCESS'),
      data: result
    }
  }

  async calculate(user: AccessTokenPayload, body: CalculateOrderBodyType) {
    // Lấy cartItems
    const cartItems = await this.prismaService.cartItem.findMany({
      where: { id: { in: body.cartItemIds }, userId: user.userId },
      include: { sku: true }
    })
    if (!cartItems.length) throw DiscountNotFoundException

    const subTotal = cartItems.reduce((sum, item) => sum + item.sku.price * item.quantity, 0)

    if (!body.discountCodes || body.discountCodes.length === 0) {
      return {
        message: this.i18n.t('order.order.success.CALCULATE_SUCCESS'),
        data: {
          subTotal,
          shippingFee: 0,
          directDiscount: 0,
          discounts: [],
          grandTotal: subTotal
        }
      }
    }

    // Lấy thông tin các discount
    const discounts = await this.prismaService.discount.findMany({
      where: {
        code: { in: body.discountCodes },
        discountStatus: DiscountStatus.ACTIVE,
        startDate: { lte: new Date() },
        endDate: { gte: new Date() },
        deletedAt: null
      },
      include: {
        products: { select: { id: true } },
        categories: { select: { id: true } },
        brands: { select: { id: true } }
      }
    })
    if (!discounts.length) throw DiscountNotFoundException

    if (body.discountCodes && Array.isArray(body.discountCodes)) {
      for (const discountCode of body.discountCodes) {
        const discount = await this.prismaService.discount.findUnique({ where: { code: discountCode } })
        if (!discount) throw DiscountNotFoundException
        // Kiểm tra maxUsesPerUser
        if (discount.maxUsesPerUser && discount.maxUsesPerUser > 0) {
          const usedCount = await this.prismaService.discountSnapshot.count({
            where: { discountId: discount.id, order: { userId: user.userId } }
          })
          if (usedCount >= discount.maxUsesPerUser) throw DiscountUsageLimitExceededException
        }
      }
    }

    const appliedDiscounts = discounts.map((discount) => {
      const discountAmount = calculateDiscountAmount(discount, subTotal)
      return {
        code: discount.code,
        name: discount.name,
        amount: discountAmount
      }
    })

    const totalDiscountAmount = appliedDiscounts.reduce((sum, d) => sum + d.amount, 0)
    const grandTotal = subTotal - totalDiscountAmount

    return {
      message: this.i18n.t('order.order.success.CALCULATE_SUCCESS'),
      data: {
        subTotal,
        shippingFee: 0,
        directDiscount: 0,
        discounts: appliedDiscounts,
        grandTotal: Math.max(0, grandTotal)
      }
    }
  }
}
