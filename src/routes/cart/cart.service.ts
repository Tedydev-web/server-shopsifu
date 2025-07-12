import { Injectable } from '@nestjs/common'
import { CartRepo } from './cart.repo'
import { AddToCartBodyType, DeleteCartBodyType, UpdateCartItemBodyType } from 'src/routes/cart/cart.model'
import { I18nContext } from 'nestjs-i18n'
import { PaginationQueryType } from 'src/shared/models/request.model'

@Injectable()
export class CartService {
  constructor(private readonly cartRepo: CartRepo) {}

  getCart(userId: number, query: PaginationQueryType) {
    return this.cartRepo.list2({
      userId,
      languageId: I18nContext.current()?.lang as string,
      page: query.page,
      limit: query.limit,
    })
  }

  addToCart(userId: number, body: AddToCartBodyType) {
    return this.cartRepo.create(userId, body)
  }

  updateCartItem({ userId, body, cartItemId }: { userId: number; cartItemId: number; body: UpdateCartItemBodyType }) {
    return this.cartRepo.update({
      userId,
      body,
      cartItemId,
    })
  }

  async deleteCart(userId: number, body: DeleteCartBodyType) {
    const { count } = await this.cartRepo.delete(userId, body)
    return {
      message: `${count} item(s) deleted from cart`,
    }
  }
}
