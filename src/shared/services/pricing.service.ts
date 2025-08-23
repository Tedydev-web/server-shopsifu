import { Injectable } from '@nestjs/common'
import { PrismaService } from 'src/shared/services/prisma.service'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'
import { calculateDiscountAmount, validateDiscountForOrder } from 'src/shared/helpers'

@Injectable()
export class PricingService {
  constructor(private readonly prisma: PrismaService) {}

  /**
   * Kiểu dữ liệu phí vận chuyển truyền vào cho từng shop
   */
  private sumShippingFees(shippingFees?: Array<{ shopId: string; fee: number }>): number {
    if (!shippingFees || shippingFees.length === 0) return 0
    return shippingFees.reduce((sum: number, s) => sum + Math.max(0, s.fee || 0), 0)
  }

  async tinhTamTinhDonHang(
    user: AccessTokenPayload,
    input: {
      shops?: Array<{
        shopId: string
        cartItemIds: string[]
        shippingFee: number
        discountCodes?: string[]
      }>
      platformDiscountCodes?: string[]
    }
  ): Promise<{
    totalItemCost: number
    totalShippingFee: number
    totalVoucherDiscount: number
    totalPayment: number
    shops?: Array<{
      shopId: string
      itemCost: number
      shippingFee: number
      voucherDiscount: number
      platformVoucherDiscount: number
      payment: number
    }>
  }> {
    // Chỉ hỗ trợ payload theo shop
    if (input.shops && input.shops.length > 0) {
      // Lấy toàn bộ cartItemIds từ tất cả shop trước (để validate và có đủ dữ liệu tính voucher)
      const allCartItemIds = Array.from(new Set(input.shops.flatMap((s) => s.cartItemIds)))
      const cartItems = await this.prisma.cartItem.findMany({
        where: { id: { in: allCartItemIds }, userId: user.userId },
        include: {
          sku: {
            include: {
              product: { include: { productTranslations: true, brand: true, categories: true } }
            }
          }
        }
      })

      if (!cartItems.length) {
        return { totalItemCost: 0, totalShippingFee: 0, totalVoucherDiscount: 0, totalPayment: 0, shops: [] }
      }

      // Map nhanh cartItemId -> cartItem
      const cartItemMap = new Map(cartItems.map((c) => [c.id, c]))

      // Tính theo từng shop
      const perShop = await Promise.all(
        input.shops.map(async (shop) => {
          const items = shop.cartItemIds.map((id) => cartItemMap.get(id)).filter(Boolean) as typeof cartItems
          const itemCost = items.reduce((sum, item) => sum + item.sku.price * item.quantity, 0)

          // Voucher ở cấp shop (nếu có)
          let shopVoucher = 0
          if (shop.discountCodes && shop.discountCodes.length > 0) {
            const discounts = await this.prisma.discount.findMany({
              where: {
                code: { in: shop.discountCodes },
                discountStatus: 'ACTIVE',
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

            if (discounts.length > 0) {
              const usage = await this.prisma.discountSnapshot.groupBy({
                by: ['discountId'],
                where: { discountId: { in: discounts.map((d) => d.id) }, order: { userId: user.userId } },
                _count: { discountId: true }
              })
              const usageMap = new Map<string, number>(
                usage.filter((u) => u.discountId !== null).map((u) => [u.discountId as string, u._count.discountId])
              )

              const productIds = items.map((i) => i.sku.product.id)
              const categoryIds = items
                .map((i) => i.sku.product.categories.map((c) => c.id))
                .flat()
                .filter(Boolean)
              const brandIds = items.map((i) => i.sku.product.brand?.id).filter((id): id is string => Boolean(id))

              const valid = discounts.filter((d) => {
                const used = usageMap.get(d.id) || 0
                return validateDiscountForOrder(d as any, itemCost, productIds, categoryIds, brandIds, used)
              })
              shopVoucher = valid.map((d) => calculateDiscountAmount(d as any, itemCost)).reduce((s, v) => s + v, 0)
            }
          }

          const shippingFee = Math.max(0, shop.shippingFee || 0)
          const itemCount = items.reduce((sum, item) => sum + item.quantity, 0)
          const payment = Math.max(0, itemCost - shopVoucher + shippingFee)
          return {
            shopId: shop.shopId,
            itemCost,
            shippingFee,
            voucherDiscount: -shopVoucher,
            payment,
            itemCount
          }
        })
      )

      // Voucher nền tảng (áp dụng trên tổng sau khi cộng từng shop)
      const sumItem = perShop.reduce((s, p) => s + p.itemCost, 0)
      const sumShip = perShop.reduce((s, p) => s + p.shippingFee, 0)
      const sumShopVoucherAbs = perShop.reduce((s, p) => s + Math.abs(p.voucherDiscount), 0)

      let platformVoucherAbs = 0
      if (input.platformDiscountCodes && input.platformDiscountCodes.length > 0) {
        const discounts = await this.prisma.discount.findMany({
          where: {
            code: { in: input.platformDiscountCodes },
            discountStatus: 'ACTIVE',
            startDate: { lte: new Date() },
            endDate: { gte: new Date() },
            deletedAt: null,
            OR: [{ voucherType: 'PLATFORM' }, { isPlatform: true }]
          },
          include: {
            products: { select: { id: true } },
            categories: { select: { id: true } },
            brands: { select: { id: true } }
          }
        })

        if (discounts.length > 0) {
          // Lấy thông tin cart items để validate discount eligibility
          const allProductIds = allCartItemIds.map((id) => cartItemMap.get(id)?.sku.product.id).filter(Boolean)
          const allCategoryIds = allCartItemIds
            .flatMap((id) => {
              const item = cartItemMap.get(id)
              return item?.sku.product.categories.map((c) => c.id) || []
            })
            .filter(Boolean)
          const allBrandIds = allCartItemIds
            .map((id) => {
              const item = cartItemMap.get(id)
              return item?.sku.product.brand?.id
            })
            .filter(Boolean)

          // Validate và filter platform discounts
          const validPlatformDiscounts = discounts.filter((discount) => {
            // Kiểm tra minOrderValue
            if (discount.minOrderValue > 0 && sumItem < discount.minOrderValue) {
              return false
            }

            // Kiểm tra discountApplyType SPECIFIC
            if (discount.discountApplyType === 'SPECIFIC') {
              const hasValidProduct =
                discount.products.length > 0 &&
                allProductIds.some((productId) => discount.products.some((p) => p.id === productId))
              const hasValidCategory =
                discount.categories.length > 0 &&
                allCategoryIds.some((categoryId) => discount.categories.some((c) => c.id === categoryId))
              const hasValidBrand =
                discount.brands.length > 0 &&
                allBrandIds.some((brandId) => discount.brands.some((b) => b.id === brandId))

              if (!hasValidProduct && !hasValidCategory && !hasValidBrand) {
                return false
              }
            }

            return true
          })

          // Tính toán platform discount amount
          platformVoucherAbs = validPlatformDiscounts
            .map((d) => calculateDiscountAmount(d as any, sumItem))
            .reduce((sum, amount) => sum + amount, 0)
        }
      }

      // Phân bổ voucher nền tảng theo tỷ lệ giá trị hàng mỗi shop
      const perShopWithPlatform = perShop.map((p) => {
        const ratio = sumItem > 0 ? p.itemCost / sumItem : 0
        const platformPart = platformVoucherAbs * ratio
        return {
          ...p,
          platformVoucherDiscount: -platformPart,
          payment: Math.max(0, p.payment - platformPart)
        }
      })

      const totalVoucherDiscount = -(sumShopVoucherAbs + platformVoucherAbs)
      const totalPayment = Math.max(
        0,
        perShopWithPlatform.reduce((s, p) => s + p.payment, 0)
      )

      return {
        totalItemCost: sumItem,
        totalShippingFee: sumShip,
        totalVoucherDiscount,
        totalPayment,
        shops: perShopWithPlatform
      }
    }

    // Nếu không có shops → coi như rỗng
    return { totalItemCost: 0, totalShippingFee: 0, totalVoucherDiscount: 0, totalPayment: 0, shops: [] }
  }
}
