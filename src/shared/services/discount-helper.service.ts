import { Injectable } from '@nestjs/common'
import { User } from '@prisma/client'
import { PrismaService } from 'src/shared/services/prisma.service'

interface CartItem {
  shopId: string
  productId: string
  quantity: number
  price: number
}

interface FilterDiscountsParams {
  orderValue: number
  productId?: string
  cart?: CartItem[]
}

interface CheckDiscountAvailableParams {
  discount: any
  user: User | null
  orderValue: number
  productId?: string
  cart?: CartItem[]
}

@Injectable()
export class DiscountHelperService {
  constructor(private readonly prismaService: PrismaService) {}

  /**
   * Lọc và phân loại các voucher khả dụng/không khả dụng cho user
   */
  async filterAvailableDiscounts(
    discounts: any[],
    user: User | null,
    params: FilterDiscountsParams
  ): Promise<{ available: any[]; unavailable: any[] }> {
    const { orderValue, productId, cart } = params
    const available: any[] = []
    const unavailable: any[] = []
    let bestChoiceIndex = -1
    let maxDiscountAmount = 0
    for (const discount of discounts) {
      const mapped = this.mapDiscount(discount)
      const reason = await this.checkDiscountAvailable({ discount: mapped, user, orderValue, productId, cart })
      let discountAmount = 0
      if (!reason) {
        discountAmount = this.calculateDiscountAmount(mapped, orderValue)
      }
      const discountWithAmount = { ...mapped, discountAmount }
      if (!reason) {
        available.push(discountWithAmount)
        if (discountAmount > maxDiscountAmount) {
          maxDiscountAmount = discountAmount
          bestChoiceIndex = available.length - 1
        }
      } else {
        unavailable.push({ ...discountWithAmount, reason })
      }
    }
    if (bestChoiceIndex !== -1) {
      available[bestChoiceIndex].isBestChoice = true
    }
    return { available, unavailable }
  }

  /**
   * Xác thực một voucher cho user và đơn hàng
   */
  async verifyDiscount(
    discount: any,
    user: User | null,
    params: FilterDiscountsParams
  ): Promise<{ isValid: boolean; reason?: string; data?: { discountAmount: number; finalPrice: number } }> {
    const { orderValue, cart } = params
    const mapped = this.mapDiscount(discount)
    const reason = await this.checkDiscountAvailable({ discount: mapped, user, orderValue, cart })
    if (reason) {
      return { isValid: false, reason }
    }
    const discountAmount = this.calculateDiscountAmount(mapped, orderValue)
    return {
      isValid: true,
      data: {
        discountAmount,
        finalPrice: orderValue - discountAmount
      }
    }
  }

  /**
   * Chuẩn hóa object discount (chỉ lấy id cho các quan hệ)
   */
  private mapDiscount(discount: any) {
    return {
      ...discount,
      products: discount.products?.map((p: any) => p.id) ?? [],
      categories: discount.categories?.map((c: any) => c.id) ?? [],
      brands: discount.brands?.map((b: any) => b.id) ?? []
    }
  }

  /**
   * Kiểm tra điều kiện áp dụng voucher (public để OrderRepo dùng)
   */
  async checkDiscountAvailable({
    discount,
    user,
    orderValue,
    productId,
    cart
  }: CheckDiscountAvailableParams): Promise<string | null> {
    const now = new Date()
    if (discount.status !== 'ACTIVE') return 'discount.discount.error.NOT_ACTIVE'
    if (new Date(discount.startDate) > now) return 'discount.discount.error.NOT_STARTED'
    if (new Date(discount.endDate) < now) return 'discount.discount.error.EXPIRED'
    if (discount.maxUses > 0 && discount.usesCount >= discount.maxUses) return 'discount.discount.error.MAX_USED'
    if (
      user &&
      discount.maxUsesPerUser > 0 &&
      discount.usersUsed.filter((id: string) => id === user.id).length >= discount.maxUsesPerUser
    )
      return 'discount.discount.error.MAX_USED_PER_USER'
    if (discount.minOrderValue > orderValue) return 'discount.discount.error.MIN_ORDER_VALUE'
    if (discount.usersUsed.includes(user?.id)) {
      return 'discount.discount.error.ALREADY_USED'
    }
    const productReason = await this.checkProductConditions(discount, cart)
    if (productReason) {
      return productReason
    }
    if (user) {
      // Logic cho anniversary, minSpend, loyalty... có thể bổ sung sau
    }
    if (discount.appliesTo === 'SPECIFIC' && !this.isApplicableForSpecificProducts(discount, cart)) {
      return 'discount.discount.error.NOT_APPLICABLE_FOR_CART'
    }
    return null
  }

  /**
   * Kiểm tra sản phẩm trong giỏ hàng có phù hợp điều kiện voucher không
   */
  private async checkProductConditions(discount: any, cart: CartItem[] | undefined): Promise<string | null> {
    if (!cart || cart.length === 0) {
      return null
    }
    const hasCategoryCondition = discount.categories && discount.categories.length > 0
    const hasBrandCondition = discount.brands && discount.brands.length > 0
    if (!hasCategoryCondition && !hasBrandCondition) {
      return null
    }
    const productIdsInCart = cart.map((item) => item.productId)
    const productsInDb = await this.prismaService.product.findMany({
      where: { id: { in: productIdsInCart } },
      select: { id: true, brandId: true, categories: { select: { id: true } } }
    })
    const productMap = new Map(productsInDb.map((p) => [p.id, p]))
    let isApplicable = false
    for (const cartItem of cart) {
      const product = productMap.get(cartItem.productId)
      if (product) {
        const productCategoryIds = new Set(product.categories.map((c) => c.id))
        const categoryMatch =
          !hasCategoryCondition || discount.categories.some((catId: string) => productCategoryIds.has(catId))
        const brandMatch = !hasBrandCondition || (product.brandId && discount.brands.includes(product.brandId))
        if (categoryMatch && brandMatch) {
          isApplicable = true
          break
        }
      }
    }
    if (!isApplicable) {
      return 'discount.discount.error.NOT_APPLICABLE_FOR_CART'
    }
    return null
  }

  /**
   * Kiểm tra sản phẩm cụ thể có nằm trong danh sách áp dụng không
   */
  private isApplicableForSpecificProducts(discount: any, cart: CartItem[] | undefined): boolean {
    if (!cart || cart.length === 0) {
      return true
    }
    const applicableProductIds = new Set(discount.products)
    return cart.some((item) => applicableProductIds.has(item.productId))
  }

  /**
   * Tính số tiền giảm giá thực tế (public để OrderRepo dùng)
   */
  calculateDiscountAmount(discount: any, orderValue: number): number {
    let discountAmount = 0
    if (discount.type === 'FIX_AMOUNT') {
      discountAmount = discount.value
    } else if (discount.type === 'PERCENTAGE') {
      discountAmount = Math.floor((orderValue * discount.value) / 100)
      if (discount.maxDiscountValue && discount.maxDiscountValue > 0 && discountAmount > discount.maxDiscountValue) {
        discountAmount = discount.maxDiscountValue
      }
    }
    return discountAmount
  }
}
