import { Injectable } from '@nestjs/common'
import { CartRepo } from './cart.repo'
import {
  AddToCartBodyType,
  DeleteCartBodyType,
  GetCartQueryType,
  UpdateCartItemBodyType,
} from 'src/routes/cart/cart.model'
import { I18nContext } from 'nestjs-i18n'

@Injectable()
export class CartService {
  constructor(private readonly cartRepo: CartRepo) {}

  getCart(userId: number, query: GetCartQueryType) {
    return this.cartRepo.list({
      ...query,
      userId,
      languageId: I18nContext.current()?.lang as string,
    })
  }

  addToCart(userId: number, body: AddToCartBodyType) {
    return this.cartRepo.create(userId, body)
  }

  updateCartItem(cartItemId: number, body: UpdateCartItemBodyType) {
    return this.cartRepo.update(cartItemId, body)
  }

  async deleteCart(userId: number, body: DeleteCartBodyType) {
    const { count } = await this.cartRepo.delete(userId, body)
    return {
      message: `${count} item(s) deleted from cart`,
    }
  }
}
