import { Injectable } from '@nestjs/common'
import { CartRepo } from './cart.repo'
import { AddToCartBodyType, DeleteCartBodyType, UpdateCartItemBodyType } from 'src/routes/cart/cart.model'
import { I18nContext } from 'nestjs-i18n'
import { PaginationQueryType } from 'src/shared/models/request.model'

@Injectable()
export class CartService {
  constructor(private readonly cartRepo: CartRepo) {}

  getCart(userId: string, query: PaginationQueryType) {
    return this.cartRepo.list({
      userId,
      languageId: I18nContext.current()?.lang as string,
      page: query.page,
      limit: query.limit
    })
  }

  addToCart(userId: string, body: AddToCartBodyType) {
    return this.cartRepo.create(userId, body)
  }

  updateCartItem({ userId, body, cartItemId }: { userId: string; cartItemId: string; body: UpdateCartItemBodyType }) {
    return this.cartRepo.update({
      userId,
      body,
      cartItemId
    })
  }

  async deleteCart(userId: string, body: DeleteCartBodyType) {
    const { count } = await this.cartRepo.delete(userId, body)
    return {
      message: `${count} item(s) deleted from cart`
    }
  }
}
