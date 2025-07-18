import { BadRequestException, Injectable } from '@nestjs/common'
import { PrismaService } from 'src/shared/services/prisma.service'
import { DiscountSchemaType } from 'src/shared/models/shared-discount.model'
import { CreateDiscountBodyType, GetDiscountDetailResType } from './discount.model'
import { DiscountStatus } from 'src/shared/constants/discount.constant'

@Injectable()
export class DiscountRepo {
  constructor(private readonly prismaService: PrismaService) {}

  // 1. Generator Discount Code [SELLER | ADMIN]
  // 2. Get Discount Amount [CLIENT]
  // 3. Get All Discounts Code [CLIENT | SELLER]
  // 4. Verify Discount Code [CLIENT]
  // 5. Delete Discount Code [SELLER | ADMIN]
  // 6. Cancel Discount Code [CLIENT]

  async create({
    createdById,
    data
  }: {
    createdById: string | null
    data: CreateDiscountBodyType
  }): Promise<GetDiscountDetailResType> {
    // Kiểm tra
    if (new Date() < new Date(data.startDate) || new Date() > new Date(data.endDate)) {
      throw new BadRequestException('Ngày bắt đầu và ngày kết thúc không hợp lệ')
    }

    return this.prismaService.discount.create({
      data: {
        ...data,
        createdById
      }
    })
  }
}
