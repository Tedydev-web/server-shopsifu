import { Injectable } from '@nestjs/common'
import { DiscountRepo } from './discount.repo'
import { VerifyDiscountBodyType } from './discount.model'
import { I18nService } from 'nestjs-i18n'
import { I18nTranslations } from 'src/shared/languages/generated/i18n.generated'
import { DiscountNotFoundException } from './discount.error'
import { PrismaService } from 'src/shared/services/prisma.service'
import { SharedDiscountRepo } from 'src/shared/repositories/shared-discount.repo'
import { DiscountHelperService } from 'src/shared/services/discount-helper.service'

@Injectable()
export class DiscountService {
  constructor(
    private readonly discountRepo: DiscountRepo,
    private readonly sharedDiscountRepo: SharedDiscountRepo,
    private readonly i18n: I18nService<I18nTranslations>,
    private readonly prismaService: PrismaService,
    private readonly discountHelper: DiscountHelperService
  ) {}

  async getAvailableDiscounts(params: {
    userId?: string
    shopId?: string | null
    productId?: string
    orderValue: number
    cart?: Array<{ shopId: string; productId: string; quantity: number; price: number }>
  }) {
    let { shopId } = params
    const { userId } = params
    if (shopId === 'null') shopId = null
    const user = userId ? await this.prismaService.user.findUnique({ where: { id: userId } }) : null
    const queries: any[] = []
    if (shopId) {
      queries.push(this.discountRepo.list({ shopId, isPublic: true, page: 1, limit: 100 }))
    } else {
      queries.push(this.discountRepo.list({ shopId: null, isPublic: true, page: 1, limit: 100 }))
    }
    const results = await Promise.all(queries)
    const allDiscountsRaw = results.flatMap((result) => result.data)
    const allDiscounts = Array.from(new Map(allDiscountsRaw.map((d) => [d.id, d])).values())
    const data = await this.discountHelper.filterAvailableDiscounts(allDiscounts, user, params)
    return {
      message: this.i18n.t('discount.discount.success.GET_SUCCESS' as any),
      data
    }
  }

  async verifyDiscounts(
    body: VerifyDiscountBodyType & {
      userId?: string
      cart?: Array<{ shopId: string; productId: string; quantity: number; price: number }>
    }
  ) {
    const { userId, code, orderValue, cart } = body
    const user = userId ? await this.prismaService.user.findUnique({ where: { id: userId } }) : null
    const discount = await this.sharedDiscountRepo.findByCode(code)
    if (!discount) {
      throw DiscountNotFoundException
    }
    const result = await this.discountHelper.verifyDiscount(discount, user, { orderValue, cart })
    if (!result.isValid) {
      throw DiscountNotFoundException
    }
    return {
      message: this.i18n.t('discount.discount.success.VERIFY_SUCCESS' as any),
      data: result.data
    }
  }
}
