import { Injectable } from '@nestjs/common'
import {
	CreateOrderBodyType,
	GetOrderListQueryType,
	GetOrderListResType
} from 'src/routes/order/order.model'
import { OrderRepo } from 'src/routes/order/order.repo'
import { I18nService } from 'nestjs-i18n'
import { I18nTranslations } from 'src/shared/languages/generated/i18n.generated'

@Injectable()
export class OrderService {
	constructor(
		private readonly orderRepo: OrderRepo,
		private readonly i18n: I18nService<I18nTranslations>
	) {}

	async list(userId: number, query: GetOrderListQueryType) {
		const result = await this.orderRepo.list(userId, query)
		return {
			...result,
			message: this.i18n.t('order.order.success.GET_SUCCESS')
		}
	}

	async create(userId: number, body: CreateOrderBodyType) {
		const order = await this.orderRepo.create(userId, body)
		return {
			data: order,
			message: this.i18n.t('order.order.success.CREATE_SUCCESS')
		}
	}

	async cancel(userId: number, orderId: number) {
		const order = await this.orderRepo.cancel(userId, orderId)
		return {
			data: order,
			message: this.i18n.t('order.order.success.CANCEL_SUCCESS')
		}
	}

	async detail(userId: number, orderId: number) {
		const order = await this.orderRepo.detail(userId, orderId)
		return {
			data: order,
			message: this.i18n.t('order.order.success.GET_DETAIL_SUCCESS')
		}
	}
}
