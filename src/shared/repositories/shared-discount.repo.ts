import { Injectable, BadRequestException } from '@nestjs/common'
import { PrismaService } from 'src/shared/services/prisma.service'
import { DiscountStatus } from 'src/shared/constants/discount.constant'
import { calculateDiscountAmount, validateDiscountForOrder, prepareDiscountSnapshotData } from 'src/shared/helpers'

type DiscountWithIncludes = {
  id: string
  code: string
  name: string
  description: string | null
  value: number
  discountType: string
  discountApplyType: string
  discountStatus: string
  startDate: Date
  endDate: Date
  maxUses: number
  maxUsesPerUser: number | null
  usesCount: number
  usersUsed: string[]
  maxDiscountValue: number | null
  minOrderValue: number | null
  isPlatform: boolean
  voucherType: string
  displayType: string
  products: { id: string }[]
  categories: { id: string }[]
  brands: { id: string }[]
}

type DiscountSnapshotData = {
  name: string
  description: string
  discountType: string
  value: number
  code: string
  maxDiscountValue: number
  discountAmount: number
  minOrderValue: number
  isPlatform: boolean
  voucherType: string
  displayType: string
  discountApplyType: string
  targetInfo: any
  discountId: string
}

@Injectable()
export class SharedDiscountRepository {
  constructor(private readonly prismaService: PrismaService) {}

  /**
   * Validate discounts cho order - Bridge method
   * Sử dụng bởi Order module để validate discounts trước khi tạo order
   */
  async validateDiscountsForOrder(
    discountCodes: string[],
    userId: string
  ): Promise<{
    discounts: DiscountWithIncludes[]
    userUsageMap: Map<string, number>
  }> {
    if (discountCodes.length === 0) {
      return {
        discounts: [],
        userUsageMap: new Map()
      }
    }

    // Lấy thông tin tất cả discounts một lần
    const discounts = await this.prismaService.discount.findMany({
      where: { code: { in: discountCodes } },
      include: {
        products: { select: { id: true } },
        categories: { select: { id: true } },
        brands: { select: { id: true } }
      }
    })

    if (discounts.length !== discountCodes.length) {
      const foundCodes = discounts.map((d) => d.code)
      const missingCodes = discountCodes.filter((code) => !foundCodes.includes(code))
      throw new BadRequestException(`Mã voucher không tồn tại: ${missingCodes.join(', ')}`)
    }

    // Lấy thông tin usage count một lần để tránh N+1 queries
    const userDiscountUsage = await this.prismaService.discountSnapshot.groupBy({
      by: ['discountId'],
      where: {
        discountId: { in: discounts.map((d) => d.id) },
        order: { userId }
      },
      _count: { discountId: true }
    })

    const userUsageMap = new Map(
      userDiscountUsage
        .filter((item) => item.discountId !== null)
        .map((item) => [item.discountId!, item._count.discountId])
    )

    return { discounts, userUsageMap }
  }

  /**
   * Lấy valid platform discounts - Bridge method
   * Sử dụng bởi Order module để lấy platform discounts
   */
  async getValidPlatformDiscounts(discountCodes: string[]): Promise<DiscountWithIncludes[]> {
    if (discountCodes.length === 0) {
      return []
    }

    const discounts = await this.prismaService.discount.findMany({
      where: {
        code: { in: discountCodes },
        discountStatus: DiscountStatus.ACTIVE,
        startDate: { lte: new Date() },
        endDate: { gte: new Date() },
        deletedAt: null,
        isPlatform: true // Chỉ lấy platform discounts
      },
      include: {
        products: { select: { id: true } },
        categories: { select: { id: true } },
        brands: { select: { id: true } }
      }
    })

    if (discounts.length !== discountCodes.length) {
      const foundCodes = discounts.map((d) => d.code)
      const missingCodes = discountCodes.filter((code) => !foundCodes.includes(code))
      throw new BadRequestException(`Mã voucher nền tảng không tồn tại: ${missingCodes.join(', ')}`)
    }

    return discounts
  }

  /**
   * Xử lý discounts cho một order - Bridge method
   * Sử dụng bởi Order module để xử lý discounts khi tạo order
   */
  async processDiscountsForOrder(
    tx: any,
    orderItem: any,
    cartItemMap: Map<string, any>,
    orderTotal: number,
    userId: string
  ): Promise<DiscountSnapshotData[]> {
    if (!orderItem.discountCodes || orderItem.discountCodes.length === 0) {
      return []
    }

    // Lấy discount info
    const { discounts } = await this.getValidDiscountsForTransaction(tx, orderItem.discountCodes, userId)

    // Validate và apply discounts
    const appliedDiscounts: DiscountSnapshotData[] = []
    const { productIds, categoryIds, brandIds } = this.extractProductInfo(orderItem.cartItemIds, cartItemMap)

    for (const discount of discounts) {
      if (validateDiscountForOrder(discount, orderTotal, productIds, categoryIds, brandIds)) {
        const discountAmount = calculateDiscountAmount(discount, orderTotal)
        const targetInfo = this.prepareDiscountTargetInfo(discount)

        appliedDiscounts.push(prepareDiscountSnapshotData(discount, discountAmount, targetInfo))

        // Update discount usage
        await tx.discount.update({
          where: { id: discount.id },
          data: {
            usesCount: { increment: 1 },
            usersUsed: { push: userId }
          }
        })
      }
    }

    return appliedDiscounts
  }

  /**
   * Xử lý platform discounts cho một shop cụ thể - Bridge method
   * Sử dụng bởi Order module để xử lý platform discounts
   */
  async processPlatformDiscountsForShop(
    tx: any,
    platformDiscounts: DiscountWithIncludes[],
    shopOrderTotal: number,
    userId: string
  ): Promise<DiscountSnapshotData[]> {
    if (platformDiscounts.length === 0) {
      return []
    }

    const appliedPlatformDiscounts: DiscountSnapshotData[] = []

    for (const discount of platformDiscounts) {
      // Tính discount amount cho shop này
      const discountAmount = calculateDiscountAmount(discount, shopOrderTotal)

      // Chuẩn bị target info
      const targetInfo = this.prepareDiscountTargetInfo(discount)

      appliedPlatformDiscounts.push(prepareDiscountSnapshotData(discount, discountAmount, targetInfo))

      // Update discount usage
      await tx.discount.update({
        where: { id: discount.id },
        data: {
          usesCount: { increment: 1 },
          usersUsed: { push: userId }
        }
      })
    }

    return appliedPlatformDiscounts
  }

  /**
   * Tạo discount snapshots - Bridge method
   * Sử dụng bởi Order module để tạo discount snapshots
   */
  async createDiscountSnapshots(tx: any, appliedDiscounts: DiscountSnapshotData[], orderId: string): Promise<void> {
    for (const discountData of appliedDiscounts) {
      await tx.discountSnapshot.create({
        data: {
          ...discountData,
          orderId
        }
      })
    }
  }

  /**
   * Lấy discount info của order - Bridge method
   * Sử dụng bởi Order module để lấy discount info khi hiển thị
   */
  async getOrderDiscountInfo(orderId: string): Promise<any[]> {
    return this.prismaService.discountSnapshot.findMany({
      where: { orderId }
    })
  }

  /**
   * Get valid discounts cho transaction - Private helper
   */
  private async getValidDiscountsForTransaction(
    tx: any,
    discountCodes: string[],
    userId: string
  ): Promise<{ discounts: DiscountWithIncludes[] }> {
    const discounts = await tx.discount.findMany({
      where: {
        code: { in: discountCodes },
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

    if (discounts.length !== discountCodes.length) {
      const foundCodes = discounts.map((d) => d.code)
      const missingCodes = discountCodes.filter((code) => !foundCodes.includes(code))
      throw new BadRequestException(`Mã voucher không tồn tại: ${missingCodes.join(', ')}`)
    }

    return { discounts }
  }

  /**
   * Extract product info từ cart items - Private helper
   */
  private extractProductInfo(cartItemIds: string[], cartItemMap: Map<string, any>) {
    const productIds = cartItemIds.map((cartItemId) => {
      const cartItem = cartItemMap.get(cartItemId)!
      return cartItem.sku.product.id
    })

    const categoryIds = cartItemIds
      .map((cartItemId) => {
        const cartItem = cartItemMap.get(cartItemId)!
        return cartItem.sku.product.categories.map((c) => c.id)
      })
      .flat()
      .filter(Boolean)

    const brandIds = cartItemIds
      .map((cartItemId) => {
        const cartItem = cartItemMap.get(cartItemId)!
        return cartItem.sku.product.brand.id
      })
      .filter(Boolean)

    return { productIds, categoryIds, brandIds }
  }

  /**
   * Chuẩn bị discount target info - Private helper
   */
  private prepareDiscountTargetInfo(discount: DiscountWithIncludes) {
    return discount.discountApplyType === 'SPECIFIC'
      ? {
          productIds: discount.products.map((p) => p.id),
          categoryIds: discount.categories.map((c) => c.id),
          brandIds: discount.brands.map((b) => b.id)
        }
      : null
  }
}
