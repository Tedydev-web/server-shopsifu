import { InjectQueue } from '@nestjs/bullmq'
import { Injectable, Logger } from '@nestjs/common'
import { Queue, JobsOptions } from 'bullmq'
import {
  CREATE_SHIPPING_ORDER_JOB,
  PROCESS_GHN_WEBHOOK_JOB,
  CANCEL_GHN_ORDER_JOB,
  CREATE_GHN_ORDER_JOB,
  SHIPPING_QUEUE_NAME
} from 'src/shared/constants/queue.constant'
import { CreateOrderType, GHNWebhookPayloadType } from 'src/routes/shipping/ghn/shipping-ghn.model'
import { generateShippingWebhookJobId } from 'src/shared/helpers'

@Injectable()
export class ShippingProducer {
  private readonly logger = new Logger(ShippingProducer.name)

  constructor(@InjectQueue(SHIPPING_QUEUE_NAME) private shippingQueue: Queue) {}

  async enqueueCreateOrder(jobData: CreateOrderType): Promise<any> {
    this.logger.log(`[SHIPPING_PRODUCER] Enqueue create order job: ${jobData.client_order_code}`)

    try {
      const jobId = `shipping-order-${jobData.client_order_code || 'unknown'}-${Date.now()}`
      this.validateShippingJobData(jobData)

      const jobOptions: JobsOptions = {
        jobId,
        removeOnComplete: 100,
        removeOnFail: 50,
        attempts: 3,
        backoff: {
          type: 'exponential',
          delay: 2000
        }
      }

      const job = await this.shippingQueue.add(CREATE_SHIPPING_ORDER_JOB, jobData, jobOptions)
      this.logger.log(`[SHIPPING_PRODUCER] Job enqueued successfully: ${job.id}`)
      return job
    } catch (error) {
      this.logger.error(`[SHIPPING_PRODUCER] Failed to enqueue job: ${error.message}`)
      throw error
    }
  }

  /**
   * Validate shipping job data
   */
  private validateShippingJobData(jobData: CreateOrderType): void {
    const requiredFields = [
      'client_order_code',
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
    ] as const

    // Check required fields
    const missingFields = requiredFields.filter((field) => !jobData[field])
    if (missingFields.length > 0) {
      throw new Error(`Missing required fields: ${missingFields.join(', ')}`)
    }

    // Validate numeric fields
    const numericFields = ['weight', 'length', 'width', 'height', 'service_id'] as const
    const invalidNumericFields = numericFields.filter((field) => {
      const value = jobData[field]
      return typeof value !== 'number' || value <= 0
    })

    if (invalidNumericFields.length > 0) {
      throw new Error(`Invalid numeric fields: ${invalidNumericFields.join(', ')}`)
    }

    // Validate phone numbers
    this.validatePhoneNumber(jobData.from_phone, 'from_phone')
    this.validatePhoneNumber(jobData.to_phone, 'to_phone')
  }

  /**
   * Validate phone number format
   */
  private validatePhoneNumber(phone: string, fieldName: string): void {
    const phoneRegex = /^(\+84|84|0)[0-9]{9}$/
    if (!phoneRegex.test(phone)) {
      throw new Error(`Invalid ${fieldName} format: ${phone}`)
    }
  }

  /**
   * Enqueue multiple shipping jobs
   */
  async enqueueMultipleShippingOrders(ordersData: CreateOrderType[]): Promise<void> {
    this.logger.log(`[SHIPPING_PRODUCER] Enqueue ${ordersData.length} shipping orders`)

    if (ordersData.length === 0) {
      this.logger.warn(`[SHIPPING_PRODUCER] No orders to enqueue`)
      return
    }

    const results = await Promise.allSettled(ordersData.map((orderData) => this.enqueueCreateOrder(orderData)))

    const successful = results.filter((result) => result.status === 'fulfilled').length
    const failed = results.filter((result) => result.status === 'rejected').length

    this.logger.log(`[SHIPPING_PRODUCER] Batch enqueue completed: ${successful} successful, ${failed} failed`)

    if (failed > 0) {
      // Log failed jobs for debugging
      results.forEach((result, index) => {
        if (result.status === 'rejected') {
          this.logger.error(`[SHIPPING_PRODUCER] Failed to enqueue order ${index}: ${result.reason}`)
        }
      })
      throw new Error(`Failed to enqueue ${failed} shipping jobs`)
    }
  }

  /**
   * Enqueue GHN webhook processing job
   */
  async enqueueWebhookProcessing(payload: GHNWebhookPayloadType): Promise<any> {
    this.logger.log(`[SHIPPING_PRODUCER] Enqueue webhook processing: ${payload.orderCode}`)

    try {
      const job = await this.shippingQueue.add(
        PROCESS_GHN_WEBHOOK_JOB,
        {
          orderCode: payload.orderCode,
          status: payload.status
        },
        {
          jobId: generateShippingWebhookJobId(payload.orderCode || 'unknown'),
          removeOnComplete: true,
          removeOnFail: true
        }
      )

      this.logger.log(`[SHIPPING_PRODUCER] Webhook job enqueued: ${job.id}`)
      return job
    } catch (error) {
      this.logger.error(`[SHIPPING_PRODUCER] Failed to enqueue webhook job: ${error.message}`)
      throw error
    }
  }

  /**
   * Enqueue job hủy đơn hàng GHN
   */
  async enqueueCancelGHNOrder(orderCode: string, orderId: string): Promise<any> {
    this.logger.log(`[SHIPPING_PRODUCER] Enqueue cancel GHN order job: ${orderCode} for order: ${orderId}`)

    try {
      const jobId = `cancel-ghn-order-${orderCode}-${Date.now()}`

      const job = await this.shippingQueue.add(
        CANCEL_GHN_ORDER_JOB,
        {
          orderCode,
          orderId
        },
        {
          jobId,
          removeOnComplete: true,
          removeOnFail: true,
          attempts: 3,
          backoff: {
            type: 'exponential',
            delay: 2000
          }
        }
      )

      this.logger.log(`[SHIPPING_PRODUCER] Cancel GHN order job enqueued: ${job.id}`)
      return job
    } catch (error) {
      this.logger.error(`[SHIPPING_PRODUCER] Failed to enqueue cancel GHN order job: ${error.message}`)
      throw error
    }
  }

  /**
   * Enqueue job tạo đơn hàng GHN
   */
  async enqueueCreateGHNOrder(orderId: string): Promise<any> {
    this.logger.log(`[SHIPPING_PRODUCER] Enqueue create GHN order job for order: ${orderId}`)

    try {
      const jobId = `create-ghn-order-${orderId}-${Date.now()}`

      const job = await this.shippingQueue.add(
        CREATE_GHN_ORDER_JOB,
        {
          orderId
        },
        {
          jobId,
          removeOnComplete: true,
          removeOnFail: true,
          attempts: 3,
          backoff: {
            type: 'exponential',
            delay: 2000
          }
        }
      )

      this.logger.log(`[SHIPPING_PRODUCER] Create GHN order job enqueued: ${job.id}`)
      return job
    } catch (error) {
      this.logger.error(`[SHIPPING_PRODUCER] Failed to enqueue create GHN order job: ${error.message}`)
      throw error
    }
  }
}
