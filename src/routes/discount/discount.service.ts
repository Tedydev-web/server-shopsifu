import { Injectable } from '@nestjs/common'
import { PrismaService } from 'src/shared/services/prisma.service'
import { DiscountRepo } from './discount.repo'
import { DiscountType, DiscountApplyType } from 'src/shared/constants/discount.constant'
import { I18nService } from 'nestjs-i18n'
import { I18nTranslations } from 'src/shared/languages/generated/i18n.generated'

@Injectable()
export class DiscountService {
  constructor(
    private readonly prismaService: PrismaService,
    private readonly discountRepo: DiscountRepo,
    private readonly i18n: I18nService<I18nTranslations>
  ) {}

  /**
   * Lấy danh sách mã giảm giá khả dụng cho checkout
   */
  async getAvailableForCheckout(cartItemIds: string[], userId?: string) {
    // 1. Lấy thông tin chi tiết giỏ hàng
    const cartItems = await this.prismaService.cartItem.findMany({
      where: { id: { in: cartItemIds } },
      include: {
        sku: {
          include: {
            product: {
              include: {
                categories: true,
                brand: true
              }
            }
          }
        }
      }
    })

    // 2. Lấy các discount khả dụng
    const discounts = await this.discountRepo.getAvailableDiscounts(cartItems, userId)

    // 3. Lọc discount phù hợp với các sản phẩm trong giỏ
    const availableDiscounts = discounts.filter((discount) => {
      if (discount.appliesTo === DiscountApplyType.ALL) {
        return true
      }

      if (discount.appliesTo === DiscountApplyType.SPECIFIC) {
        return this.checkDiscountTargetMatch(discount, cartItems)
      }

      return false
    })

    return {
      message: this.i18n.t('discount.discount.success.GET_AVAILABLE_SUCCESS' as any),
      data: availableDiscounts.map((discount) => ({
        id: discount.id,
        name: discount.name,
        description: discount.description,
        type: discount.type,
        value: discount.value,
        code: discount.code,
        maxDiscountValue: discount.maxDiscountValue,
        minOrderValue: discount.minOrderValue,
        appliesTo: discount.appliesTo
      }))
    }
  }

  /**
   * Tính toán giá đơn hàng với discount
   */
  async calculateOrder(cartItemIds: string[], discountCodes: string[]) {
    // 1. Lấy thông tin chi tiết giỏ hàng
    const cartItems = await this.prismaService.cartItem.findMany({
      where: { id: { in: cartItemIds } },
      include: {
        sku: {
          include: {
            product: true
          }
        }
      }
    })

    // 2. Tính giá trước discount
    const subTotal = cartItems.reduce((sum, item) => sum + item.sku.price * item.quantity, 0)

    if (!discountCodes || discountCodes.length === 0) {
      return {
        message: this.i18n.t('discount.discount.success.CALCULATE_SUCCESS' as any),
        data: {
          subTotal,
          shippingFee: 0,
          directDiscount: 0,
          discounts: [],
          grandTotal: subTotal
        }
      }
    }

    // 3. Lấy thông tin các discount
    const discounts = await this.discountRepo.getDiscountsByCodes(discountCodes)

    // 4. Tính toán giá trị giảm giá cho từng mã
    const appliedDiscounts = discounts.map((discount) => {
      const discountAmount = this.calculateDiscountAmount(discount, subTotal)
      return {
        code: discount.code,
        name: discount.name,
        amount: discountAmount
      }
    })

    // 5. Tính tổng giá cuối cùng
    const totalDiscountAmount = appliedDiscounts.reduce((sum, d) => sum + d.amount, 0)
    const grandTotal = subTotal - totalDiscountAmount

    return {
      message: this.i18n.t('discount.discount.success.CALCULATE_SUCCESS' as any),
      data: {
        subTotal,
        shippingFee: 0,
        directDiscount: 0,
        discounts: appliedDiscounts,
        grandTotal: Math.max(0, grandTotal) // Đảm bảo không âm
      }
    }
  }

  /**
   * Kiểm tra discount có áp dụng được cho các sản phẩm trong giỏ không
   */
  private checkDiscountTargetMatch(discount: any, cartItems: any[]): boolean {
    for (const cartItem of cartItems) {
      const product = cartItem.sku.product

      // Kiểm tra sản phẩm cụ thể
      if (discount.products.some((p: any) => p.id === product.id)) {
        return true
      }

      // Kiểm tra danh mục
      if (
        product.categories.some((cat: any) => discount.categories.some((discountCat: any) => discountCat.id === cat.id))
      ) {
        return true
      }

      // Kiểm tra thương hiệu
      if (product.brand && discount.brands.some((brand: any) => brand.id === product.brand.id)) {
        return true
      }
    }

    return false
  }

  /**
   * Tính số tiền giảm giá thực tế
   */
  calculateDiscountAmount(discount: any, orderTotal: number): number {
    let discountAmount = 0

    if (discount.type === DiscountType.FIX_AMOUNT) {
      discountAmount = discount.value
    } else if (discount.type === DiscountType.PERCENTAGE) {
      discountAmount = Math.floor(orderTotal * (discount.value / 100))

      // Áp dụng giới hạn tối đa nếu có
      if (discount.maxDiscountValue && discountAmount > discount.maxDiscountValue) {
        discountAmount = discount.maxDiscountValue
      }
    }

    // Đảm bảo discount không vượt quá giá trị đơn hàng
    return Math.min(discountAmount, orderTotal)
  }
}
