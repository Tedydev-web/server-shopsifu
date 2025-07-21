import { Injectable } from '@nestjs/common'
import { DiscountRepo } from './discount.repo'
import {
  CreateDiscountBodyType,
  UpdateDiscountBodyType,
  DiscountListQueryType,
  DiscountParamsType,
  VerifyDiscountBodyType
} from './discount.model'
import { I18nService } from 'nestjs-i18n'
import { I18nTranslations } from 'src/shared/languages/generated/i18n.generated'
import {
  DiscountCodeAlreadyExistsException,
  DiscountNotFoundException,
  DiscountUnauthorizedException
} from './discount.error'

@Injectable()
export class DiscountService {
  constructor(
    private readonly discountRepo: DiscountRepo,
    private readonly i18n: I18nService<I18nTranslations>
  ) {}

  async create({
    data,
    createdById,
    roleName
  }: {
    data: CreateDiscountBodyType
    createdById: string
    roleName: string
  }) {
    if (roleName !== 'ADMIN' && (!data.shopId || data.shopId !== createdById)) {
      throw DiscountUnauthorizedException
    }
    const { data: existing } = await this.discountRepo.list({
      shopId: data.shopId ?? undefined,
      page: 1,
      limit: 1,
      search: data.code
    })
    if (existing.some((d) => d.code === data.code)) {
      throw DiscountCodeAlreadyExistsException
    }
    return this.discountRepo.create({
      createdById,
      data: {
        ...data,
        createdById: createdById ?? null,
        updatedById: null,
        deletedById: null
      }
    })
  }

  async update({
    id,
    data,
    updatedById,
    roleName
  }: {
    id: string
    data: UpdateDiscountBodyType
    updatedById: string
    roleName: string
  }) {
    const discount = await this.discountRepo.findById(id)
    if (!discount) throw DiscountNotFoundException
    if (roleName !== 'ADMIN' && discount.shopId !== updatedById) {
      throw DiscountUnauthorizedException
    }
    return this.discountRepo.update({ id, updatedById, data })
  }

  async delete({
    id,
    deletedById,
    roleName,
    isHard
  }: {
    id: string
    deletedById: string
    roleName: string
    isHard?: boolean
  }) {
    const discount = await this.discountRepo.findById(id)
    if (!discount) throw DiscountNotFoundException
    if (roleName !== 'ADMIN' && discount.shopId !== deletedById) {
      throw DiscountUnauthorizedException
    }
    return this.discountRepo.delete({ id, deletedById }, isHard)
  }

  async list(query: DiscountListQueryType & { roleName: string; userId: string }) {
    const shopId = query.roleName === 'ADMIN' ? (query.shopId ?? undefined) : query.userId
    const page = query.page || 1
    const limit = query.limit || 10
    const result = await this.discountRepo.list({ ...query, shopId, page, limit })
    return {
      message: this.i18n.t('global.global.success.GET_SUCCESS'),
      ...result
    }
  }

  async detail({ id, roleName, userId }: { id: string; roleName: string; userId: string }) {
    const discount = await this.discountRepo.findById(id)
    if (!discount) throw DiscountNotFoundException
    if (roleName !== 'ADMIN' && discount.shopId !== userId) {
      throw DiscountUnauthorizedException
    }
    return {
      message: this.i18n.t('global.global.success.GET_DETAIL_SUCCESS'),
      data: discount
    }
  }

  /**
   * Lấy danh sách voucher khả dụng cho cart/order (CLIENT/Guest)
   * @param params: { userId?: string, shopId?: string, productId?: string, orderValue: number, cart: {shopId, productId, quantity, price}[] }
   */
  async getAvailableDiscounts(params: {
    userId?: string
    shopId?: string
    productId?: string
    orderValue: number
    cart?: Array<{ shopId: string; productId: string; quantity: number; price: number }>
  }) {
    // Lấy tất cả voucher phù hợp (shop, sàn, sản phẩm)
    const { userId, shopId, productId, orderValue, cart } = params
    // Lấy voucher shop
    let shopVouchers: any[] = []
    if (shopId) {
      const { data } = await this.discountRepo.list({ shopId, isPublic: true, status: 'ACTIVE', page: 1, limit: 100 })
      shopVouchers = data.filter(
        (v) => v.appliesTo === 'ALL' // || (v.appliesTo === 'SPECIFIC' && (!productId || v.products?.includes(productId)))
        // Nếu muốn filter theo sản phẩm, cần lấy products từ relation hoặc DTO chi tiết
      )
    }
    // Lấy voucher sàn
    const { data: platformVouchers } = await this.discountRepo.list({
      shopId: undefined,
      isPublic: true,
      status: 'ACTIVE',
      page: 1,
      limit: 100
    })
    // Gộp lại
    const allVouchers = [...shopVouchers, ...platformVouchers]
    // Phân loại khả dụng/không khả dụng
    const available: any[] = []
    const unavailable: any[] = []
    for (const voucher of allVouchers) {
      const reason = this.checkVoucherAvailable({ voucher, userId, orderValue, productId, cart })
      if (!reason) available.push(voucher)
      else unavailable.push({ ...voucher, reason })
    }
    return { available, unavailable }
  }

  /**
   * Kiểm tra điều kiện voucher, trả về lý do nếu không khả dụng
   */
  private checkVoucherAvailable({
    voucher,
    userId,
    orderValue,
    productId,
    cart
  }: {
    voucher: any
    userId?: string
    orderValue: number
    productId?: string
    cart?: Array<{ shopId: string; productId: string; quantity: number; price: number }>
  }): string | null {
    const now = new Date()
    if (voucher.status !== 'ACTIVE') return 'Voucher không hoạt động'
    if (voucher.startDate > now) return 'Voucher chưa bắt đầu'
    if (voucher.endDate < now) return 'Voucher đã hết hạn'
    if (voucher.maxUses > 0 && voucher.usesCount >= voucher.maxUses) return 'Voucher đã hết lượt sử dụng'
    if (
      userId &&
      voucher.maxUsesPerUser > 0 &&
      voucher.usersUsed.filter((id: string) => id === userId).length >= voucher.maxUsesPerUser
    )
      return 'Bạn đã dùng hết lượt'
    if (voucher.minOrderValue > orderValue) return `Đơn hàng chưa đủ giá trị tối thiểu`
    if (
      voucher.appliesTo === 'SPECIFIC' &&
      productId &&
      voucher.products &&
      !voucher.products.map((p: any) => p.id).includes(productId)
    ) {
      return 'Voucher không áp dụng cho sản phẩm này'
    }
    return null
  }

  /**
   * API verify/apply voucher cho CLIENT (tính tổng giảm giá, validate, ghi nhận sử dụng nếu apply)
   * @param body: VerifyDiscountBodyType & { apply?: boolean, cart: {shopId, productId, quantity, price}[] }
   */
  async verifyDiscounts(
    body: VerifyDiscountBodyType & {
      apply?: boolean
      cart: Array<{ shopId: string; productId: string; quantity: number; price: number }>
    }
  ) {
    const { userId, code, orderValue, productIds, apply, cart } = body
    // Tìm voucher theo code
    const { data: vouchers } = await this.discountRepo.list({
      search: code,
      isPublic: true,
      status: 'ACTIVE',
      page: 1,
      limit: 10
    })
    const voucher = vouchers.find((v) => v.code === code)
    if (!voucher) throw DiscountNotFoundException
    // Kiểm tra điều kiện
    const reason = this.checkVoucherAvailable({ voucher, userId, orderValue, productId: productIds?.[0], cart })
    if (reason) throw DiscountUnauthorizedException
    // Tính số tiền giảm giá
    let discountAmount = 0
    if (voucher.type === 'FIX_AMOUNT') discountAmount = voucher.value
    else if (voucher.type === 'PERCENTAGE') discountAmount = Math.floor((orderValue * voucher.value) / 100)
    // Nếu apply, ghi nhận sử dụng
    if (apply && userId) {
      // Tăng usesCount, thêm userId vào usersUsed
      await this.discountRepo.update({
        id: voucher.id,
        updatedById: userId,
        data: {
          usesCount: voucher.usesCount + 1,
          usersUsed: [...voucher.usersUsed, userId]
        }
      })
    }
    return {
      discountAmount,
      voucher: {
        code: voucher.code,
        type: voucher.type,
        value: voucher.value,
        shopId: voucher.shopId,
        appliesTo: voucher.appliesTo
      }
    }
  }
}
