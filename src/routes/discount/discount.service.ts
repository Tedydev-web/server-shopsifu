import { Injectable } from '@nestjs/common'
import { PrismaService } from 'src/shared/services/prisma.service'
import { DiscountRepo } from './discount.repo'
import { DiscountApplyType } from 'src/shared/constants/discount.constant'
import { I18nService } from 'nestjs-i18n'
import { I18nTranslations } from 'src/shared/languages/generated/i18n.generated'
import { DiscountNotFoundException } from './discount.error'

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
  async getAvailableForCheckout({ cartItemIds, userId }: { cartItemIds: string[]; userId?: string }) {
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
    if (!cartItems.length) throw DiscountNotFoundException

    // 2. Lấy các discount khả dụng
    const discounts = await this.discountRepo.getAvailableDiscounts(cartItems, userId)

    // 3. Lọc discount phù hợp với các sản phẩm trong giỏ
    const availableDiscounts = discounts.filter((discount) => {
      if (discount.discountApplyType === DiscountApplyType.ALL) {
        return true
      }
      if (discount.discountApplyType === DiscountApplyType.SPECIFIC) {
        return this.checkDiscountTargetMatch(discount, cartItems)
      }
      return false
    })

    return {
      message: this.i18n.t('discount.discount.success.GET_AVAILABLE_SUCCESS'),
      data: availableDiscounts.map((discount) => ({
        id: discount.id,
        name: discount.name,
        description: discount.description,
        discountType: discount.discountType,
        value: discount.value,
        code: discount.code,
        maxDiscountValue: discount.maxDiscountValue,
        discountAmount: 0, // Chưa tính toán ở bước này, sẽ tính khi đặt hàng
        minOrderValue: discount.minOrderValue,
        isPlatform: discount.isPlatform,
        voucherType: discount.voucherType,
        displayType: discount.displayType,
        discountApplyType: discount.discountApplyType,
        targetInfo:
          discount.discountApplyType === DiscountApplyType.SPECIFIC
            ? {
                productIds: discount.products?.map((p: any) => p.id) || [],
                categoryIds: discount.categories?.map((c: any) => c.id) || [],
                brandIds: discount.brands?.map((b: any) => b.id) || []
              }
            : null
      }))
    }
  }

  /**
   * Kiểm tra discount có áp dụng được cho các sản phẩm trong giỏ không
   */
  private checkDiscountTargetMatch(discount: any, cartItems: any[]): boolean {
    for (const cartItem of cartItems) {
      const product = cartItem.sku.product
      if (discount.products.some((p: any) => p.id === product.id)) {
        return true
      }
      if (
        product.categories.some((cat: any) => discount.categories.some((discountCat: any) => discountCat.id === cat.id))
      ) {
        return true
      }
      if (product.brand && discount.brands.some((brand: any) => brand.id === product.brand.id)) {
        return true
      }
    }
    return false
  }
}
