import { Injectable } from '@nestjs/common'
import { DiscountRepo } from './discount.repo'
import { GetDiscountsQueryType, VerifyDiscountBodyType } from './discount.model'
import { I18nService } from 'nestjs-i18n'
import { I18nTranslations } from 'src/shared/languages/generated/i18n.generated'
import { DiscountNotFoundException, DiscountUnauthorizedException } from './discount.error'
import { NotFoundRecordException } from 'src/shared/error'

@Injectable()
export class DiscountService {
  constructor(
    private readonly discountRepo: DiscountRepo,
    private readonly i18n: I18nService<I18nTranslations>
  ) {}

  async list(query: GetDiscountsQueryType) {
    const data = await this.discountRepo.list({ ...query, isPublic: true, status: 'ACTIVE' })
    return {
      message: this.i18n.t('global.global.success.GET_SUCCESS'),
      data: data.data.map((d) => ({ ...d, products: d.products?.map((p) => p.id) ?? [] })),
      metadata: data.metadata
    }
  }

  async getDetail(id: string) {
    const discount = await this.discountRepo.findById(id)
    if (!discount || !discount.isPublic) {
      throw NotFoundRecordException
    }
    return {
      message: this.i18n.t('global.global.success.GET_DETAIL_SUCCESS'),
      data: { ...discount, products: discount.products?.map((p) => p.id) ?? [] }
    }
  }

  async getAvailableDiscounts(params: {
    userId?: string
    shopId?: string | null
    productId?: string
    orderValue: number
    cart?: Array<{ shopId: string; productId: string; quantity: number; price: number }>
  }) {
    let { shopId } = params
    const { userId, productId, orderValue, cart } = params
    if (shopId === 'null') shopId = null

    const queries: any[] = []
    // 1. Lấy voucher của shop (nếu có shopId)
    if (shopId) {
      queries.push(this.discountRepo.list({ shopId, isPublic: true, status: 'ACTIVE', page: 1, limit: 100 }))
    }
    // 2. Lấy voucher toàn sàn
    queries.push(this.discountRepo.list({ shopId: null, isPublic: true, status: 'ACTIVE', page: 1, limit: 100 }))

    const results = await Promise.all(queries)
    const allDiscountsRaw = results.flatMap((result) => result.data)

    // Lọc trùng lặp voucher (phòng trường hợp query trả về trùng)
    const allDiscounts = Array.from(new Map(allDiscountsRaw.map((d) => [d.id, d])).values())

    const available: any[] = []
    const unavailable: any[] = []

    for (const discount of allDiscounts) {
      const mappedDiscount = {
        ...discount,
        products: discount.products?.map((p) => p.id) ?? []
      }
      const reason = this.checkDiscountAvailable({ discount: mappedDiscount, userId, orderValue, productId, cart })
      if (!reason) {
        available.push(mappedDiscount)
      } else {
        unavailable.push({ ...mappedDiscount, reason })
      }
    }
    return {
      message: this.i18n.t('global.global.success.GET_SUCCESS'),
      data: { available, unavailable }
    }
  }

  private checkDiscountAvailable({
    discount,
    userId,
    orderValue,
    productId,
    cart
  }: {
    discount: any
    userId?: string
    orderValue: number
    productId?: string
    cart?: Array<{ shopId: string; productId: string; quantity: number; price: number }>
  }): string | null {
    const now = new Date()
    if (discount.status !== 'ACTIVE') return 'Voucher không hoạt động'
    if (new Date(discount.startDate) > now) return 'Voucher chưa bắt đầu'
    if (new Date(discount.endDate) < now) return 'Voucher đã hết hạn'
    if (discount.maxUses > 0 && discount.usesCount >= discount.maxUses) return 'Voucher đã hết lượt sử dụng'
    if (
      userId &&
      discount.maxUsesPerUser > 0 &&
      discount.usersUsed.filter((id: string) => id === userId).length >= discount.maxUsesPerUser
    )
      return 'Bạn đã dùng hết lượt sử dụng voucher này'
    if (discount.minOrderValue > orderValue) return `Cần mua tối thiểu ${discount.minOrderValue} để áp dụng`
    if (discount.appliesTo === 'SPECIFIC' && productId && discount.products && !discount.products.includes(productId)) {
      return 'Voucher không áp dụng cho sản phẩm này'
    }
    return null
  }

  async verifyDiscounts(
    body: VerifyDiscountBodyType & {
      userId?: string
      apply?: boolean
      cart?: Array<{ shopId: string; productId: string; quantity: number; price: number }>
    }
  ) {
    const { userId, code, orderValue, cart, apply } = body

    const discount = await this.discountRepo.findByCode(code)

    if (!discount) {
      throw DiscountNotFoundException
    }

    const mappedDiscount = {
      ...discount,
      products: discount.products?.map((p) => p.id) ?? []
    }

    const reason = this.checkDiscountAvailable({ discount: mappedDiscount, userId, orderValue, cart })
    if (reason) {
      throw new DiscountUnauthorizedException(reason)
    }

    let discountAmount = 0
    if (discount.type === 'FIX_AMOUNT') {
      discountAmount = discount.value
    } else if (discount.type === 'PERCENTAGE') {
      discountAmount = Math.floor((orderValue * discount.value) / 100)
    }

    if (apply && userId) {
      await this.discountRepo.update({
        id: discount.id,
        updatedById: userId,
        data: {
          usesCount: discount.usesCount + 1,
          usersUsed: [...discount.usersUsed, userId]
        }
      })
    }

    return {
      message: this.i18n.t('global.global.success.GET_SUCCESS'),
      data: {
        discountAmount,
        discount: {
          code: discount.code,
          type: discount.type,
          value: discount.value,
          shopId: discount.shopId,
          appliesTo: discount.appliesTo
        }
      }
    }
  }
}
