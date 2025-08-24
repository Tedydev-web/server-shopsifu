import { Processor, WorkerHost } from '@nestjs/bullmq'
import { Injectable } from '@nestjs/common'
import { Job } from 'bullmq'
import { Inject } from '@nestjs/common'
import { GHN_CLIENT } from 'src/shared/constants/shipping.constants'
import { OrderShippingStatus } from 'src/shared/constants/order-shipping.constants'
import { PrismaService } from 'src/shared/services/prisma.service'
import {
  CREATE_SHIPPING_ORDER_JOB,
  PROCESS_GHN_WEBHOOK_JOB,
  SHIPPING_QUEUE_NAME
} from 'src/shared/constants/queue.constant'
import { CreateOrderType, GHNWebhookPayloadType } from 'src/routes/shipping/ghn/shipping-ghn.model'
import { Ghn } from 'giaohangnhanh'
import { OrderStatus } from 'src/shared/constants/order.constant'

@Injectable()
@Processor(SHIPPING_QUEUE_NAME, {
  concurrency: 2,
  maxStalledCount: 1,
  stalledInterval: 30000
})
export class ShippingConsumer extends WorkerHost {
  constructor(
    @Inject(GHN_CLIENT) private readonly ghn: Ghn,
    private readonly prismaService: PrismaService
  ) {
    super()
  }

  async process(job: Job<CreateOrderType | GHNWebhookPayloadType>) {
    try {
      if (job.name === CREATE_SHIPPING_ORDER_JOB) {
        return this.processCreateOrder(job as Job<CreateOrderType>)
      }

      if (job.name === PROCESS_GHN_WEBHOOK_JOB) {
        return this.processWebhook(job as Job<GHNWebhookPayloadType>)
      }

      throw new Error(`Unknown job type: ${job.name}`)
    } catch (error) {
      throw error
    }
  }

  /**
   * Xử lý tạo shipping order
   */
  private async processCreateOrder(job: Job<CreateOrderType>) {
    try {
      const { client_order_code } = job.data

      if (!client_order_code) {
        throw new Error('Missing client_order_code')
      }

      const orderId = this.extractOrderId(client_order_code)
      const existingShipping = await this.findExistingShipping(orderId)

      if (existingShipping && this.isOrderAlreadyProcessed(existingShipping)) {
        return {
          message: 'Order already has GHN shipping order',
          orderCode: existingShipping.orderCode
        }
      }

      const ghnResponse = await this.createGHNOrder(job.data)
      const orderShipping = await this.updateOrderShipping(orderId, ghnResponse)

      return {
        message: 'Shipping order created successfully',
        orderCode: ghnResponse.order_code,
        orderShippingId: orderShipping.id
      }
    } catch (error) {
      if (job.data.client_order_code) {
        await this.handleCreateOrderError(job.data.client_order_code, error)
      }
      throw error
    }
  }

  /**
   * Xử lý GHN webhook trong background
   */
  private async processWebhook(job: Job<GHNWebhookPayloadType>) {
    try {
      const { orderCode, status } = job.data

      if (!orderCode || !status) {
        throw new Error('Missing required fields: orderCode or status')
      }

      const shipping = await this.findShippingWithOrder(orderCode)
      if (!shipping) {
        return { message: 'No shipping record found', orderCode: orderCode }
      }

      const newOrderStatus = this.mapGHNStatusToOrderStatus(status)
      if (!newOrderStatus) {
        return { message: 'Unknown status, keeping current order status', orderCode: orderCode, status: status }
      }

      if (shipping.order.status !== newOrderStatus) {
        await this.updateOrderStatus(shipping.orderId, newOrderStatus)
      }

      return {
        message: 'Webhook processed successfully',
        orderCode: orderCode,
        oldStatus: shipping.order.status,
        newStatus: newOrderStatus,
        ghnStatus: status
      }
    } catch (error) {
      const enhancedError = new Error(
        `Webhook processing failed for orderCode: ${job.data.orderCode}. ${error.message}`
      )
      enhancedError.stack = error.stack
      throw enhancedError
    }
  }

  /**
   * Helper methods
   */
  private extractOrderId(clientOrderCode: string): string {
    return clientOrderCode.startsWith('SSPX') ? clientOrderCode.substring(4) : clientOrderCode
  }

  private async findExistingShipping(orderId: string) {
    return this.prismaService.orderShipping.findUnique({
      where: { orderId }
    })
  }

  private isOrderAlreadyProcessed(shipping: any): boolean {
    return (
      shipping?.status === OrderShippingStatus.CREATED &&
      shipping?.orderCode &&
      shipping?.orderCode !== 'TEMP_ORDER_CODE'
    )
  }

  private async createGHNOrder(orderData: CreateOrderType) {
    const ghnResponse = await this.ghn.order.createOrder(orderData)

    if (!ghnResponse?.order_code) {
      throw new Error('Failed to create GHN order: Invalid response')
    }

    return ghnResponse
  }

  private async updateOrderShipping(
    orderId: string,
    ghnResponse: { order_code: string; expected_delivery_time?: string | Date }
  ) {
    return this.prismaService.orderShipping.update({
      where: { orderId },
      data: {
        orderCode: ghnResponse.order_code,
        expectedDeliveryTime: ghnResponse.expected_delivery_time ? new Date(ghnResponse.expected_delivery_time) : null,
        status: OrderShippingStatus.CREATED,
        attempts: { increment: 1 },
        lastUpdatedAt: new Date()
      }
    })
  }

  private async handleCreateOrderError(clientOrderCode: string, error: Error) {
    if (!clientOrderCode) return

    await this.prismaService.orderShipping.update({
      where: { orderId: this.extractOrderId(clientOrderCode) },
      data: {
        status: OrderShippingStatus.FAILED,
        lastError: error.message.substring(0, 255),
        attempts: { increment: 1 }
      }
    })
  }

  private async findShippingWithOrder(orderCode: string) {
    return this.prismaService.orderShipping.findFirst({
      where: { orderCode },
      include: { order: true }
    })
  }

  private async updateOrderStatus(orderId: string, newStatus: (typeof OrderStatus)[keyof typeof OrderStatus]) {
    return this.prismaService.order.update({
      where: { id: orderId },
      data: { status: newStatus }
    })
  }

  /**
   * Map GHN status sang OrderStatus (6 trạng thái hệ thống)
   */
  private mapGHNStatusToOrderStatus(ghnStatus: string): (typeof OrderStatus)[keyof typeof OrderStatus] | null {
    const statusMap: Record<string, (typeof OrderStatus)[keyof typeof OrderStatus]> = {
      // Tạo đơn hàng
      ready_to_pick: OrderStatus.PENDING_PICKUP,

      // Lấy hàng
      picking: OrderStatus.PENDING_PICKUP,
      picked: OrderStatus.PENDING_PICKUP,

      // Vận chuyển
      storing: OrderStatus.PENDING_DELIVERY,
      transporting: OrderStatus.PENDING_DELIVERY,
      sorting: OrderStatus.PENDING_DELIVERY,
      delivering: OrderStatus.PENDING_DELIVERY,

      // Giao hàng
      delivered: OrderStatus.DELIVERED,
      delivery_fail: OrderStatus.PENDING_DELIVERY,

      // Trả hàng
      waiting_to_return: OrderStatus.RETURNED,
      return: OrderStatus.RETURNED,
      return_transporting: OrderStatus.RETURNED,
      return_sorting: OrderStatus.RETURNED,
      returning: OrderStatus.RETURNED,
      returned: OrderStatus.RETURNED,

      // Ngoại lệ
      exception: OrderStatus.CANCELLED,
      damage: OrderStatus.CANCELLED,
      lost: OrderStatus.CANCELLED,
      cancel: OrderStatus.CANCELLED
    }

    const mappedStatus = statusMap[ghnStatus]

    return mappedStatus || null
  }
}
