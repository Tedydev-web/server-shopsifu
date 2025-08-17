import { Injectable } from '@nestjs/common'
import { CartRepo } from './cart.repo'
import { AddToCartBodyType, DeleteCartBodyType, UpdateCartItemBodyType } from 'src/routes/cart/cart.model'
import { I18nContext } from 'nestjs-i18n'
import { PaginationQueryType } from 'src/shared/models/request.model'
import { I18nService } from 'nestjs-i18n'
import { I18nTranslations } from 'src/shared/languages/generated/i18n.generated'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'

@Injectable()
export class CartService {
  constructor(
    private readonly cartRepo: CartRepo,
    private readonly i18n: I18nService<I18nTranslations>
  ) {}

  async getCart(user: AccessTokenPayload, query: PaginationQueryType) {
    const data = await this.cartRepo.list({
      userId: user.userId,
      languageId: I18nContext.current()?.lang as string,
      page: query.page,
      limit: query.limit
    })
    return {
      message: this.i18n.t('cart.cart.success.GET_SUCCESS'),
      data: data.data,
      metadata: data.metadata
    }
  }

  async addToCart(user: AccessTokenPayload, body: AddToCartBodyType) {
    const cart = await this.cartRepo.create(user.userId, body)
    return {
      message: this.i18n.t('cart.cart.success.CREATE_SUCCESS'),
      data: cart
    }
  }

  async updateCartItem({
    user,
    body,
    cartItemId
  }: {
    user: AccessTokenPayload
    cartItemId: string
    body: UpdateCartItemBodyType
  }) {
    const cartItem = await this.cartRepo.update({
      userId: user.userId,
      body,
      cartItemId
    })
    return {
      message: this.i18n.t('cart.cart.success.UPDATE_SUCCESS'),
      data: cartItem
    }
  }

  async deleteCart(user: AccessTokenPayload, body: DeleteCartBodyType) {
    const { count } = await this.cartRepo.delete(user.userId, body)
    return {
      message: this.i18n.t('cart.cart.success.DELETE_SUCCESS'),
      data: { count }
    }
  }
}
