import { Injectable } from '@nestjs/common'
import { PrismaService } from 'src/shared/services/prisma.service'
import { DiscountType } from 'src/shared/models/shared-discount.model'

@Injectable()
export class SharedDiscountRepo {
  constructor(private readonly prismaService: PrismaService) {}

  /**
   * Tìm discount theo id
   */
  async findById(id: string): Promise<DiscountType | null> {
    return this.prismaService.discount.findUnique({
      where: { id, deletedAt: null },
      include: {
        products: true,
        categories: true,
        brands: true
      }
    })
  }

  /**
   * Tìm discount theo code
   */
  async findByCode(code: string): Promise<DiscountType | null> {
    return this.prismaService.discount.findFirst({
      where: { code, deletedAt: null },
      include: {
        products: true,
        categories: true,
        brands: true
      }
    })
  }

  /**
   * Tăng lượt sử dụng discount cho user
   */
  async applyUsage(id: string, userId: string): Promise<DiscountType> {
    return this.prismaService.discount.update({
      where: { id },
      data: {
        usesCount: {
          increment: 1
        },
        usersUsed: {
          push: userId
        }
      }
    })
  }

  /**
   * Giảm lượt sử dụng discount cho user (rollback)
   */
  async releaseUsage(id: string, userId: string): Promise<DiscountType | null> {
    const discount = await this.findById(id)
    if (!discount) {
      return null
    }
    const userIndex = discount.usersUsed.indexOf(userId)
    if (userIndex > -1) {
      const newUsersUsed = [...discount.usersUsed]
      newUsersUsed.splice(userIndex, 1)
      return this.prismaService.discount.update({
        where: { id },
        data: {
          usesCount: {
            decrement: 1
          },
          usersUsed: {
            set: newUsersUsed
          }
        }
      })
    }
    return discount
  }
}
