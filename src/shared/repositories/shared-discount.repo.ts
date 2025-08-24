import { Injectable } from '@nestjs/common'
import { PrismaService } from 'src/shared/services/prisma.service'
import { DiscountStatus } from 'src/shared/constants/discount.constant'

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

@Injectable()
export class SharedDiscountRepository {
  constructor(private readonly prismaService: PrismaService) {}

  // ============================================================
  // DATA ACCESS METHODS - Repository Pattern
  // ============================================================

  /**
   * Lấy discounts theo codes - Bridge method
   * Sử dụng bởi Order module để lấy discount data
   */
  async findDiscountsByCodes(discountCodes: string[]): Promise<DiscountWithIncludes[]> {
    if (discountCodes.length === 0) {
      return []
    }

    return this.prismaService.discount.findMany({
      where: { code: { in: discountCodes } },
      include: {
        products: { select: { id: true } },
        categories: { select: { id: true } },
        brands: { select: { id: true } }
      }
    })
  }

  /**
   * Lấy platform discounts theo codes - Bridge method
   * Sử dụng bởi Order module để lấy platform discount data
   */
  async findPlatformDiscountsByCodes(discountCodes: string[]): Promise<DiscountWithIncludes[]> {
    if (discountCodes.length === 0) {
      return []
    }

    return this.prismaService.discount.findMany({
      where: {
        code: { in: discountCodes },
        discountStatus: DiscountStatus.ACTIVE,
        startDate: { lte: new Date() },
        endDate: { gte: new Date() },
        deletedAt: null,
        isPlatform: true
      },
      include: {
        products: { select: { id: true } },
        categories: { select: { id: true } },
        brands: { select: { id: true } }
      }
    })
  }

  /**
   * Lấy active discounts theo codes trong transaction - Bridge method
   * Sử dụng bởi Order module để lấy valid discounts
   */
  async findActiveDiscountsByCodes(tx: any, discountCodes: string[]): Promise<DiscountWithIncludes[]> {
    return tx.discount.findMany({
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
  }

  /**
   * Lấy usage count của user cho discounts - Bridge method
   * Sử dụng bởi Order module để kiểm tra usage limit
   */
  async getUserDiscountUsage(userId: string, discountIds: string[]): Promise<Map<string, number>> {
    const userDiscountUsage = await this.prismaService.discountSnapshot.groupBy({
      by: ['discountId'],
      where: {
        discountId: { in: discountIds },
        order: { userId }
      },
      _count: { discountId: true }
    })

    return new Map(
      userDiscountUsage
        .filter((item) => item.discountId !== null)
        .map((item) => [item.discountId!, item._count.discountId])
    )
  }

  /**
   * Update discount usage count - Bridge method
   * Sử dụng bởi Order module để update usage khi apply discount
   */
  async updateDiscountUsage(tx: any, discountId: string, userId: string): Promise<void> {
    await tx.discount.update({
      where: { id: discountId },
      data: {
        usesCount: { increment: 1 },
        usersUsed: { push: userId }
      }
    })
  }

  /**
   * Tạo discount snapshot trong transaction - Bridge method
   * Sử dụng bởi Order module để tạo discount snapshot
   */
  async createDiscountSnapshot(tx: any, discountSnapshotData: any, orderId: string): Promise<void> {
    await tx.discountSnapshot.create({
      data: {
        ...discountSnapshotData,
        orderId
      }
    })
  }

  /**
   * Lấy discount snapshots của order - Bridge method
   * Sử dụng bởi Order module để lấy discount info khi hiển thị
   */
  async findDiscountSnapshotsByOrderId(orderId: string): Promise<any[]> {
    return this.prismaService.discountSnapshot.findMany({
      where: { orderId }
    })
  }
}
