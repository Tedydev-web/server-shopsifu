import { Injectable } from '@nestjs/common'
import { DiscountRepo } from './discount.repo'
import { CreateDiscountBodyType, GetDiscountsQueryType, UpdateDiscountBodyType } from './discount.model'
import {
  DiscountCodeAlreadyExistsException,
  DiscountExpiredException,
  DiscountInactiveException,
  DiscountMinOrderValueException,
  DiscountNotFoundException,
  DiscountUsageExceededException,
  DiscountUserUsageExceededException
} from './discount.error'
import { DiscountStatus } from 'src/shared/constants/discount.constant'
import { DiscountSchemaType } from 'src/shared/models/shared-discount.model'

@Injectable()
export class DiscountService {
  constructor(private readonly discountRepo: DiscountRepo) {}

  async createDiscount(
    data: CreateDiscountBodyType & { shopId: string; createdById: string }
  ): Promise<DiscountSchemaType> {
    // Kiểm tra code đã tồn tại chưa
    const existed = await this.discountRepo.findByCode(data.code)
    if (existed) throw DiscountCodeAlreadyExistsException
    return this.discountRepo.create({
      ...data,
      usesCount: 0,
      usersUsed: [],
      status: DiscountStatus.DRAFT,
      shopId: data.shopId,
      createdById: data.createdById,
      updatedById: data.createdById
      })
  }

  async getDiscounts(query: GetDiscountsQueryType) {
    const discounts = query.shopId
      ? await this.discountRepo.findManyByShop(query.shopId)
      : await this.discountRepo.findAll({ status: query.status, now: query.now })
    return {
      message: 'Lấy danh sách mã giảm giá thành công',
      data: discounts,
      totalItems: discounts.length
    }
  }

  async getDiscountDetail(discountId: string) {
    const discount = await this.discountRepo.findById(discountId)
    if (!discount) throw DiscountNotFoundException
    return {
      message: 'Lấy chi tiết mã giảm giá thành công',
      data: discount
    }
  }

  async updateDiscount(discountId: string, data: UpdateDiscountBodyType, updatedById: string) {
    const discount = await this.discountRepo.findById(discountId)
    if (!discount) throw DiscountNotFoundException
    return this.discountRepo.update(discountId, { ...data, updatedById })
  }

  async deleteDiscount(discountId: string, deletedById: string) {
    const discount = await this.discountRepo.findById(discountId)
    if (!discount) throw DiscountNotFoundException
    await this.discountRepo.softDelete(discountId, deletedById)
    return { message: 'Xóa mã giảm giá thành công' }
  }

  async getProductsByDiscountCode(code: string) {
    const productIds = await this.discountRepo.getProductIdsByDiscountCode(code)
    return { message: 'Lấy danh sách sản phẩm áp dụng mã giảm giá thành công', data: productIds }
  }

  async getDiscountAmount({ code, userId, orderValue }: { code: string; userId: string; orderValue: number }) {
    const discount = await this.discountRepo.findByCode(code)
    if (!discount) throw DiscountNotFoundException
    if (discount.status !== DiscountStatus.ACTIVE) throw DiscountInactiveException
    const now = new Date()
    if (discount.startDate > now || discount.endDate < now) throw DiscountExpiredException
    if (discount.usesCount >= discount.maxUsed) throw DiscountUsageExceededException
    if (discount.minOrderValue > orderValue) throw DiscountMinOrderValueException
    // Kiểm tra số lần user đã dùng
    const hasUsed = await this.discountRepo.hasUserUsedDiscount(discount.id, userId)
    if (hasUsed && discount.maxUsesPerUser <= 1) throw DiscountUserUsageExceededException
    // Tính toán số tiền giảm
    let amount = 0
    if (discount.type === 'FIX_AMOUNT') amount = discount.value
    else if (discount.type === 'PERCENTAGE') amount = Math.floor((orderValue * discount.value) / 100)
    return { message: 'Tính toán số tiền giảm giá thành công', data: { amount, discount } }
  }
}
