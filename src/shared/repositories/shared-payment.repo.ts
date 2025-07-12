import { Injectable } from '@nestjs/common'
import { OrderStatus } from '@prisma/client'
import { PaymentStatus } from 'src/shared/constants/payment.constant'
import { DatabaseService } from 'src/shared/database/services/database.service'

@Injectable()
export class SharedPaymentRepository {
	constructor(private readonly databaseService: DatabaseService) {}

	async cancelPaymentAndOrder(paymentId: number) {
		const payment = await this.databaseService.payment.findUnique({
			where: {
				id: paymentId
			},
			include: {
				orders: {
					include: {
						items: true
					}
				}
			}
		})
		if (!payment) {
			throw Error('Payment not found')
		}
		const { orders } = payment
		const productSKUSnapshots = orders.map(order => order.items).flat()
		await this.databaseService.$transaction(async tx => {
			const updateOrder$ = tx.order.updateMany({
				where: {
					id: {
						in: orders.map(order => order.id)
					},
					status: OrderStatus.PENDING_PAYMENT,
					deletedAt: null
				},
				data: {
					status: OrderStatus.CANCELLED
				}
			})

			const updateSkus$ = Promise.all(
				productSKUSnapshots
					.filter(item => item.skuId)
					.map(item =>
						tx.sKU.update({
							where: {
								id: item.skuId as number
							},
							data: {
								stock: {
									increment: item.quantity
								}
							}
						})
					)
			)

			const updatePayment$ = tx.payment.update({
				where: {
					id: paymentId
				},
				data: {
					status: PaymentStatus.FAILED
				}
			})
			return await Promise.all([updateOrder$, updateSkus$, updatePayment$])
		})
	}
}
