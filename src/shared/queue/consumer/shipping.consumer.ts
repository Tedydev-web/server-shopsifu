import { Processor, WorkerHost } from '@nestjs/bullmq'
import { Injectable, Logger } from '@nestjs/common'
import { Job } from 'bullmq'
import { Inject } from '@nestjs/common'
import { GHN_CLIENT } from 'src/shared/constants/shipping.constants'
import { OrderShippingStatus } from 'src/shared/constants/order-shipping.constants'
import { PrismaService } from 'src/shared/services/prisma.service'
import { SHIPPING_QUEUE_NAME } from 'src/shared/constants/queue.constant'
import { CreateOrderType } from 'src/routes/shipping/shipping.model'
import { Ghn } from 'giaohangnhanh'

@Injectable()
@Processor(SHIPPING_QUEUE_NAME)
export class ShippingConsumer extends WorkerHost {
  private readonly logger = new Logger(ShippingConsumer.name)

  constructor(
    @Inject(GHN_CLIENT) private readonly ghn: Ghn,
    private readonly prismaService: PrismaService
  ) {
    super()
  }

  async process(job: Job<CreateOrderType>) {
    try {
      this.logger.log(`Processing shipping order creation for job ${job.id}`)

      const orderData = job.data

      // Kiểm tra xem order đã có shipping chưa (idempotency)
      if (job.data.client_order_code) {
        const existingShipping = await this.prismaService.orderShipping.findUnique({
          where: {
            orderId: job.data.client_order_code.startsWith('SSPX')
              ? job.data.client_order_code.substring(4)
              : job.data.client_order_code
          }
        })

        if (!existingShipping) {
          this.logger.error(`No OrderShipping record found for order ${job.data.client_order_code}`)
          throw new Error(`No OrderShipping record found for order ${job.data.client_order_code}`)
        }

        if (
          existingShipping.status === OrderShippingStatus.CREATED &&
          existingShipping.orderCode &&
          existingShipping.orderCode !== 'TEMP_ORDER_CODE'
        ) {
          this.logger.log(
            `Order ${job.data.client_order_code} already has GHN shipping order ${existingShipping.orderCode}, skipping`
          )
          return { message: 'Order already has GHN shipping order', orderCode: existingShipping.orderCode }
        }

        // Kiểm tra trạng thái của OrderShipping
        if (existingShipping.status !== OrderShippingStatus.ENQUEUED) {
          this.logger.warn(
            `OrderShipping for ${job.data.client_order_code} has unexpected status: ${existingShipping.status}`
          )
        }
      }

      // Tạo GHN order
      const ghnResponse = await this.ghn.order.createOrder(orderData)

      if (!ghnResponse || !ghnResponse.order_code) {
        // Cập nhật trạng thái OrderShipping thành FAILED
        if (orderData.client_order_code) {
          await this.prismaService.orderShipping.update({
            where: { orderId: orderData.client_order_code },
            data: {
              status: OrderShippingStatus.FAILED,
              lastError: 'Failed to create GHN order: Invalid response',
              attempts: { increment: 1 }
            }
          })
        }
        throw new Error('Failed to create GHN order: Invalid response')
      }

      // Cập nhật thông tin shipping vào database
      const orderShipping = await this.prismaService.orderShipping.update({
        where: { orderId: (job.data.client_order_code || '').replace(/^SSPX/, '') },
        data: {
          orderCode: ghnResponse.order_code,
          expectedDeliveryTime: ghnResponse.expected_delivery_time
            ? new Date(ghnResponse.expected_delivery_time)
            : null,
          status: OrderShippingStatus.CREATED,
          attempts: { increment: 1 },
          lastUpdatedAt: new Date()
        }
      })
      this.logger.log(`Order ${orderData.client_order_code} status remains PENDING_PAYMENT`)

      this.logger.log(
        `Successfully created shipping order ${ghnResponse.order_code} for order ${orderData.client_order_code}`
      )

      return {
        message: 'Shipping order created successfully',
        orderCode: ghnResponse.order_code,
        orderShippingId: orderShipping.id
      }
    } catch (error) {
      this.logger.error(`Failed to process shipping order creation: ${error.message}`, error.stack)

      // Cập nhật trạng thái OrderShipping thành FAILED nếu có lỗi
      if (job.data.client_order_code) {
        try {
          await this.prismaService.orderShipping.update({
            where: { orderId: job.data.client_order_code },
            data: {
              status: OrderShippingStatus.FAILED,
              lastError: `${error.message}`.substring(0, 255), // Giới hạn độ dài của lỗi
              attempts: { increment: 1 }
            }
          })
        } catch (updateError) {
          this.logger.error(`Failed to update OrderShipping status: ${updateError.message}`)
        }
      }

      throw error
    }
  }
}
