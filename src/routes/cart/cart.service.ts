import { Injectable } from '@nestjs/common'
import { CartRepo } from './cart.repo'
import {
	AddToCartBodyType,
	DeleteCartBodyType,
	UpdateCartItemBodyType
} from 'src/routes/cart/cart.model'
import { I18nContext, I18nService } from 'nestjs-i18n'
import { PaginationQueryType } from 'src/shared/models/request.model'
import { PaginationArgs } from 'src/shared/utils/pagination.util'
import { I18nTranslations } from 'src/shared/languages/generated/i18n.generated'

@Injectable()
export class CartService {
	constructor(
		private readonly cartRepo: CartRepo,
		private readonly i18n: I18nService<I18nTranslations>
	) {}

	async getCart(userId: number, pagination: PaginationQueryType) {
		const paginationArgs: PaginationArgs = {
			page: pagination.page,
			limit: pagination.limit,
			search: pagination.search,
			sortBy: pagination.sortBy,
			orderBy: pagination.orderBy
		}

		const result = await this.cartRepo.list({
			userId,
			languageId: I18nContext.current()?.lang as string,
			pagination: paginationArgs
		})

		return {
			data: result.data,
			metadata: result.metadata,
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
