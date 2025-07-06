import { Injectable } from '@nestjs/common'
import { CartRepo } from './cart.repo'
import { AddToCartBodyType, DeleteCartBodyType, UpdateCartItemBodyType } from 'src/routes/cart/cart.model'
import { I18nContext, I18nService } from 'nestjs-i18n'
import { PaginationQueryType } from 'src/shared/models/pagination.model'
import { PaginationService } from 'src/shared/services/pagination.service'
import { I18nTranslations } from 'src/shared/i18n/generated/i18n.generated'

@Injectable()
export class CartService {
  constructor(
    private readonly cartRepo: CartRepo,
    private readonly paginationService: PaginationService,
    private readonly i18n: I18nService<I18nTranslations>
  ) {}

  async getCart(userId: number, pagination: PaginationQueryType) {
    const languageId = I18nContext.current()?.lang as string

    // Sử dụng logic đặc biệt của cart để lấy data
    const result = await this.cartRepo.list2({
      userId,
      languageId,
      page: pagination.page,
      limit: pagination.limit
    })

    // Tạo metadata chuẩn từ PaginationService
    const metadata = this.paginationService.createPaginationMetadata(pagination, result.totalItems)

    return {
      data: result.data,
      metadata,
      message: this.i18n.t('cart.cart.success.GET_SUCCESS')
    }
  }

  async addToCart(userId: number, body: AddToCartBodyType) {
    const cartItem = await this.cartRepo.create(userId, body)

    return {
      data: cartItem,
      message: this.i18n.t('cart.cart.success.CREATE_SUCCESS')
    }
  }

  async updateCartItem({
    userId,
    body,
    cartItemId
  }: {
    userId: number
    cartItemId: number
    body: UpdateCartItemBodyType
  }) {
    const cartItem = await this.cartRepo.update({
      userId,
      body,
      cartItemId
    })

    return {
      data: cartItem,
      message: this.i18n.t('cart.cart.success.UPDATE_SUCCESS')
    }
  }

  async deleteCart(userId: number, body: DeleteCartBodyType) {
    const { count } = await this.cartRepo.delete(userId, body)
    return {
      message: this.i18n.t('cart.cart.success.DELETE_SUCCESS')
    }
  }
}
