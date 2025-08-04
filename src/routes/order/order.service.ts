import { BadRequestException, Injectable } from '@nestjs/common'
import { CreateOrderBodyType, GetOrderListQueryType, CalculateOrderBodyType } from 'src/routes/order/order.model'
import { OrderRepo } from 'src/routes/order/order.repo'
import { I18nService } from 'nestjs-i18n'
import { I18nTranslations } from 'src/shared/languages/generated/i18n.generated'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'
import { PrismaService } from 'src/shared/services/prisma.service'
import { calculateDiscountAmount, validateDiscountForOrder } from 'src/shared/helpers'
import {
  DiscountUsageLimitExceededException,
  DiscountNotApplicableException,
  DiscountExpiredException
} from 'src/routes/discount/discount.error'
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
    // Thu thập tất cả discount codes
    const allDiscountCodes = body
      .filter((shop) => shop.discountCodes && Array.isArray(shop.discountCodes))
      .flatMap((shop) => shop.discountCodes)
      .filter((code): code is string => code !== undefined)

    if (allDiscountCodes.length > 0) {
      // Lấy thông tin tất cả discounts một lần
      const discounts = await this.prismaService.discount.findMany({
        where: { code: { in: allDiscountCodes } },
        include: {
          products: { select: { id: true } },
          categories: { select: { id: true } },
          brands: { select: { id: true } }
        }
      })

      if (discounts.length !== allDiscountCodes.length) {
        const foundCodes = discounts.map((d) => d.code)
        const missingCodes = allDiscountCodes.filter((code) => !foundCodes.includes(code))
        throw new BadRequestException(`Mã voucher không tồn tại: ${missingCodes.join(', ')}`)
      }

      // Lấy thông tin usage count một lần để tránh N+1 queries
      const userDiscountUsage = await this.prismaService.discountSnapshot.groupBy({
        by: ['discountId'],
        where: {
          discountId: { in: discounts.map((d) => d.id) },
          order: { userId: user.userId }
        },
        _count: { discountId: true }
      })

      const userUsageMap = new Map(userDiscountUsage.map((item) => [item.discountId, item._count.discountId]))

      for (const discount of discounts) {
        // Kiểm tra trạng thái và thời gian
        if (discount.discountStatus !== 'ACTIVE') {
          throw DiscountNotApplicableException
        }

        const now = new Date()
        if (now < discount.startDate || now > discount.endDate) {
          throw DiscountExpiredException
        }

        // Kiểm tra maxUses
        if (discount.maxUses > 0 && discount.usesCount >= discount.maxUses) {
          throw DiscountUsageLimitExceededException
        }

        // Kiểm tra maxUsesPerUser
        if (discount.maxUsesPerUser && discount.maxUsesPerUser > 0) {
          const usedCount = userUsageMap.get(discount.id) || 0
          if (usedCount >= discount.maxUsesPerUser) throw DiscountUsageLimitExceededException
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
      data: result.data
    }
  }

  async calculate(user: AccessTokenPayload, body: CalculateOrderBodyType) {
    // Lấy cartItems
    const cartItems = await this.prismaService.cartItem.findMany({
      where: { id: { in: body.cartItemIds }, userId: user.userId },
      include: {
        sku: {
          include: {
            product: {
              include: {
                productTranslations: true,
                brand: true,
                categories: true
              }
            }
          }
        }
      }
    })

    if (!cartItems.length) {
      return {
        message: this.i18n.t('order.order.success.CALCULATE_SUCCESS'),
        data: {
          totalItemCost: 0,
          totalShippingFee: 0,
          totalVoucherDiscount: 0,
          totalPayment: 0
        }
      }
    }

    const totalPayment = cartItems.reduce((sum, item) => sum + item.sku.price * item.quantity, 0)

    if (!body.discountCodes || body.discountCodes.length === 0) {
      return {
        message: this.i18n.t('order.order.success.CALCULATE_SUCCESS'),
        data: {
          totalItemCost: totalPayment,
          totalShippingFee: 0,
          totalVoucherDiscount: 0,
          totalPayment: totalPayment
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

    if (!discounts.length) {
      return {
        message: this.i18n.t('order.order.success.CALCULATE_SUCCESS'),
        data: {
          totalItemCost: totalPayment,
          totalShippingFee: 0,
          totalVoucherDiscount: 0,
          totalPayment: totalPayment
        }
      }
    }

    // Chuẩn bị dữ liệu để kiểm tra eligibility
    const productIds = cartItems.map((item) => item.sku.product.id)
    const categoryIds = cartItems
      .map((item) => item.sku.product.categories.map((c) => c.id))
      .flat()
      .filter(Boolean)
    const brandIds = cartItems.map((item) => item.sku.product.brand.id).filter(Boolean)

    // Lấy thông tin user usage count một lần để tránh N+1 queries
    const userDiscountUsage = await this.prismaService.discountSnapshot.groupBy({
      by: ['discountId'],
      where: {
        discountId: { in: discounts.map((d) => d.id) },
        order: { userId: user.userId }
      },
      _count: { discountId: true }
    })

    const userUsageMap = new Map(userDiscountUsage.map((item) => [item.discountId, item._count.discountId]))

    // Lọc và validate discounts
    const validDiscounts = discounts.filter((discount) => {
      const userUsageCount = userUsageMap.get(discount.id) || 0
      return validateDiscountForOrder(discount, totalPayment, productIds, categoryIds, brandIds, userUsageCount)
    })

    // Tính toán discount amounts
    const appliedDiscounts = validDiscounts.map((discount) => {
      const discountAmount = calculateDiscountAmount(discount, totalPayment)
      return {
        code: discount.code,
        name: discount.name,
        amount: discountAmount
      }
    })

    const totalVoucherDiscountAmount = appliedDiscounts.reduce((sum, d) => sum + d.amount, 0)
    const grandTotal = totalPayment - totalVoucherDiscountAmount

    return {
      message: this.i18n.t('order.order.success.CALCULATE_SUCCESS'),
      data: {
        totalItemCost: totalPayment,
        totalShippingFee: 0,
        totalVoucherDiscount: -totalVoucherDiscountAmount,
        totalPayment: Math.max(0, grandTotal)
      }
    }
  }
}
