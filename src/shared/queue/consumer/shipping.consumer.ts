import { Processor, WorkerHost } from '@nestjs/bullmq'
import { Injectable, Logger } from '@nestjs/common'
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
  private readonly logger = new Logger(ShippingConsumer.name)

  constructor(
    @Inject(GHN_CLIENT) private readonly ghnClient: Ghn,
    private readonly prismaService: PrismaService
  ) {
    super()
  }

  async process(job: Job<CreateOrderType | GHNWebhookPayloadType, any, string>): Promise<any> {
    this.logger.log(`[SHIPPING_CONSUMER] Xử lý job: ${job.id} - ${job.name}`)

    try {
      switch (job.name) {
        case CREATE_SHIPPING_ORDER_JOB:
          return await this.processCreateShippingOrder(job.data as CreateOrderType)
        case PROCESS_GHN_WEBHOOK_JOB:
          return await this.processWebhook(job as Job<GHNWebhookPayloadType>)
        default:
          throw new Error(`Unknown job type: ${job.name}`)
      }
    } catch (error) {
      this.logger.error(`[SHIPPING_CONSUMER] Lỗi job ${job.id}: ${error.message}`)
      await this.handleJobError(job, error)
      throw error
    }
  }

  /**
   * Xử lý tạo shipping order
   */
  private async processCreateShippingOrder(data: CreateOrderType) {
    const orderId = this.extractOrderIdFromClientOrderCode(data.client_order_code)
    if (!orderId) {
      throw new Error(`Invalid client_order_code: ${data.client_order_code}`)
    }

    const existingShipping = await this.findExistingShipping(orderId)
    if (!existingShipping) {
      throw new Error(`OrderShipping not found for order: ${orderId}`)
    }

    if (this.isOrderAlreadyProcessed(existingShipping)) {
      return { message: 'Order already processed', orderCode: existingShipping.orderCode }
    }

    await this.updateOrderShippingStatus(orderId, OrderShippingStatus.ENQUEUED)

    const ghnResult = await this.createGHNOrder(data)
    await this.updateOrderShippingWithGHNResponse(orderId, ghnResult)

    return {
      message: 'Shipping order created successfully',
      orderCode: ghnResult.order_code,
      expectedDeliveryTime: ghnResult.expected_delivery_time
    }
  }

  /**
   * Xử lý GHN webhook
   */
  private async processWebhook(job: Job<GHNWebhookPayloadType>) {
    const { orderCode, status } = job.data
    if (!orderCode || !status) {
      throw new Error('Missing required fields: orderCode or status')
    }

    const shipping = await this.findShippingWithOrder(orderCode)
    if (!shipping) {
      return { message: 'No shipping record found', orderCode }
    }

    const newOrderStatus = this.mapGHNStatusToOrderStatus(status)
    if (!newOrderStatus) {
      return { message: 'Unknown status, keeping current', orderCode, status }
    }

    // Chỉ cho phép GHN cập nhật order từ PENDING_PICKUP trở đi
    const allowedStatuses = [
      OrderStatus.PENDING_PICKUP,
      OrderStatus.PENDING_DELIVERY,
      OrderStatus.DELIVERED,
      OrderStatus.RETURNED,
      OrderStatus.CANCELLED
    ]

    if (!allowedStatuses.includes(shipping.order.status as any)) {
      return {
        message: 'Order not ready for GHN status update',
        orderCode,
        currentStatus: shipping.order.status,
        ghnStatus: status
      }
    }

    if (shipping.order.status !== newOrderStatus) {
      await this.updateOrderStatus(shipping.orderId, newOrderStatus)
    }

    return {
      message: 'Webhook processed successfully',
      orderCode,
      oldStatus: shipping.order.status,
      newStatus: newOrderStatus,
      ghnStatus: status
    }
  }

  /**
   * Helper methods
   */
  private extractOrderIdFromClientOrderCode(clientOrderCode: string | null): string | null {
    if (!clientOrderCode) return null
    const match = clientOrderCode.match(/SSPX(.+)/)
    return match ? match[1] : null
  }

  private isOrderAlreadyProcessed(shipping: any): boolean {
    return !!(shipping.orderCode && ['CREATED', 'PROCESSING'].includes(shipping.status))
  }

  private async updateOrderShippingStatus(orderId: string, status: string, errorMessage?: string): Promise<void> {
    const updateData: any = {
      status,
      lastUpdatedAt: new Date(),
      attempts: { increment: 1 }
    }

    if (errorMessage) {
      updateData.lastError = errorMessage
    }

    await this.prismaService.orderShipping.updateMany({
      where: { orderId },
      data: updateData
    })
  }

  private async updateOrderShippingWithGHNResponse(orderId: string, ghnResponse: any): Promise<void> {
    const updateData = {
      orderCode: ghnResponse.order_code,
      expectedDeliveryTime: new Date(ghnResponse.expected_delivery_time),
      status: OrderShippingStatus.CREATED,
      attempts: { increment: 1 },
      lastUpdatedAt: new Date(),
      lastError: null
    }

    await this.prismaService.orderShipping.updateMany({
      where: { orderId },
      data: updateData
    })
  }

  private async createGHNOrder(data: CreateOrderType): Promise<any> {
    this.validateGHNOrderData(data)
    const ghnResponse = await this.ghnClient.order.createOrder(data)

    if (!ghnResponse.order_code) {
      throw new Error(`GHN API response missing order_code: ${JSON.stringify(ghnResponse)}`)
    }

    return ghnResponse
  }

  private validateGHNOrderData(data: CreateOrderType): void {
    const requiredFields = [
      'from_address',
      'from_name',
      'from_phone',
      'to_address',
      'to_name',
      'to_phone',
      'service_id',
      'weight',
      'length',
      'width',
      'height'
    ]

    const missingFields = requiredFields.filter((field) => !data[field])
    if (missingFields.length > 0) {
      throw new Error(`Missing required fields: ${missingFields.join(', ')}`)
    }

    if (data.weight <= 0 || data.length <= 0 || data.width <= 0 || data.height <= 0) {
      throw new Error(
        `Invalid dimensions: weight=${data.weight}, length=${data.length}, width=${data.width}, height=${data.height}`
      )
    }
  }

  private async handleJobError(job: Job, error: Error): Promise<void> {
    if (job.name === CREATE_SHIPPING_ORDER_JOB) {
      const orderId = this.extractOrderIdFromClientOrderCode((job.data as CreateOrderType).client_order_code)
      if (orderId) {
        await this.updateOrderShippingStatus(orderId, OrderShippingStatus.FAILED, error.message)
      }
    }
  }

  private async findExistingShipping(orderId: string) {
    return this.prismaService.orderShipping.findUnique({
      where: { orderId }
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
   * Map GHN status sang OrderStatus
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

    return statusMap[ghnStatus] || null
  }
}
