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
import { SepayQRService } from 'src/shared/services/sepay-qr.service'

@Injectable()
export class OrderService {
  constructor(
    private readonly orderRepo: OrderRepo,
    private readonly i18n: I18nService<I18nTranslations>,
    private readonly prismaService: PrismaService,
    private readonly sepayQRService: SepayQRService
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
    // Tính toán grandTotal cho từng shop order để validate
    const ordersWithGrandTotal = await Promise.all(
      body.map(async (shopOrder) => {
        // Gọi hàm calculate để tính grandTotal
        const calculateResult = await this.calculate(user, {
          cartItemIds: shopOrder.cartItemIds,
          discountCodes: shopOrder.discountCodes || []
        })

        return {
          ...shopOrder,
          calculatedGrandTotal: calculateResult.data.grandTotal
        }
      })
    )

    // Validate discount codes trước khi tạo order
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

    // Tạo order với body gốc (không bao gồm calculatedGrandTotal)
    const result = await this.orderRepo.create(user.userId, body)

    // Tính tổng tiền từ các orders đã tính toán
    const totalAmount = ordersWithGrandTotal.reduce((sum, order) => sum + order.calculatedGrandTotal, 0)

    console.log('Debug - ordersWithGrandTotal:', JSON.stringify(ordersWithGrandTotal, null, 2))
    console.log('Debug - totalAmount:', totalAmount)
    console.log('Debug - totalAmount type:', typeof totalAmount)
    console.log('Debug - result.paymentId:', result.paymentId)

    // Validate totalAmount
    if (totalAmount <= 0) {
      console.error('Error: totalAmount is invalid:', totalAmount)
      throw new Error('Invalid total amount for payment')
    }

    // Tạo QR code với số tiền chính xác
    const sepayQR = this.sepayQRService.generateQRCode(result.paymentId, totalAmount)

    console.log('Debug - sepayQR:', sepayQR)

    return {
      message: this.i18n.t('order.order.success.CREATE_SUCCESS'),
      data: {
        ...result,
        sepay_qr: sepayQR
      }
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
