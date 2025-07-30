import { Injectable } from '@nestjs/common'
import { DiscountRepo } from './discount.repo'
import { GetDiscountsQueryType } from './discount.model'
import { DiscountNotFoundException } from './discount.error'

@Injectable()
export class DiscountService {
  constructor(private readonly discountRepo: DiscountRepo) {}

  async list(query: GetDiscountsQueryType) {
    const { data, metadata } = await this.discountRepo.list({
      ...query,
      createdById: 'system'
    })

    return {
      message: 'discount.discount.success.GET_SUCCESS',
      data,
      metadata
    }
  }

  async getDetail(discountId: string) {
    const discount = await this.discountRepo.findById(discountId)
    if (!discount) {
      throw DiscountNotFoundException
    }

    return {
      message: 'discount.discount.success.GET_SUCCESS',
      data: discount
    }
  }

  async validateCode(code: string) {
    const discount = await this.discountRepo.findByCode(code)

    if (!discount) {
      return {
        message: 'discount.discount.success.VALIDATE_SUCCESS',
        data: {
          isValid: false,
          error: 'Mã voucher không tồn tại'
        }
      }
    }

    // Kiểm tra trạng thái
    if (discount.discountStatus !== 'ACTIVE') {
      return {
        message: 'discount.discount.success.VALIDATE_SUCCESS',
        data: {
          isValid: false,
          error: 'Mã voucher không còn hiệu lực'
        }
      }
    }

    // Kiểm tra thời gian
    const now = new Date()
    if (now < discount.startDate || now > discount.endDate) {
      return {
        message: 'discount.discount.success.VALIDATE_SUCCESS',
        data: {
          isValid: false,
          error: 'Mã voucher không còn hiệu lực'
        }
      }
    }

    // Kiểm tra số lần sử dụng
    if (discount.maxUses > 0 && discount.usesCount >= discount.maxUses) {
      return {
        message: 'discount.discount.success.VALIDATE_SUCCESS',
        data: {
          isValid: false,
          error: 'Mã voucher đã hết lượt sử dụng'
        }
      }
    }

    return {
      message: 'discount.discount.success.VALIDATE_SUCCESS',
      data: {
        isValid: true,
        discount
      }
    }
  }
}
