import { Injectable } from '@nestjs/common'
import { CartRepo } from './cart.repo'
import { AddToCartBodyType, DeleteCartBodyType, UpdateCartItemBodyType } from 'src/routes/cart/cart.model'
import { I18nContext } from 'nestjs-i18n'
import { PaginationQueryType } from 'src/shared/models/pagination.model'
import { PaginationService } from 'src/shared/services/pagination.service'

@Injectable()
export class CartService {
  constructor(
    private readonly cartRepo: CartRepo,
    private readonly paginationService: PaginationService,
  ) {}

  async getCart(userId: number, pagination: PaginationQueryType) {
    const languageId = I18nContext.current()?.lang as string

    // Sử dụng logic đặc biệt của cart để lấy data
    const result = await this.cartRepo.list2({
      userId,
      languageId,
      page: pagination.page,
      limit: pagination.limit,
    })

    // Tạo metadata chuẩn từ PaginationService
    const metadata = this.paginationService.createPaginationMetadata(pagination, result.totalItems)

    return {
      data: result.data,
      metadata,
    }
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
