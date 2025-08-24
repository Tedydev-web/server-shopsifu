import { InjectQueue } from '@nestjs/bullmq'
import { Injectable, Logger } from '@nestjs/common'
import { Queue, JobsOptions } from 'bullmq'
import {
  CREATE_SHIPPING_ORDER_JOB,
  PROCESS_GHN_WEBHOOK_JOB,
  SHIPPING_QUEUE_NAME
} from 'src/shared/constants/queue.constant'
import { CreateOrderType, GHNWebhookPayloadType } from 'src/routes/shipping/ghn/shipping-ghn.model'
import { generateShippingWebhookJobId } from 'src/shared/helpers'

@Injectable()
export class ShippingProducer {
  private readonly logger = new Logger(ShippingProducer.name)

  constructor(@InjectQueue(SHIPPING_QUEUE_NAME) private shippingQueue: Queue) {}

  async enqueueCreateOrder(jobData: CreateOrderType) {
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
      this.logger.log(`[SHIPPING_PRODUCER] Job enqueued: ${job.id}`)

      return job
    } catch (error) {
      this.logger.error(`[SHIPPING_PRODUCER] Enqueue failed: ${error.message}`)
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
    ]

    const missingFields = requiredFields.filter((field) => !jobData[field])
    if (missingFields.length > 0) {
      throw new Error(`Missing required fields: ${missingFields.join(', ')}`)
    }

    // Validate numeric fields
    const numericFields = ['weight', 'length', 'width', 'height', 'service_id']
    const invalidNumericFields = numericFields.filter((field) => {
      const value = jobData[field]
      return typeof value !== 'number' || value <= 0
    })

    if (invalidNumericFields.length > 0) {
      throw new Error(`Invalid numeric fields: ${invalidNumericFields.join(', ')}`)
    }

    // Validate phone number format
    const phoneRegex = /^(\+84|84|0)[0-9]{9}$/
    if (!phoneRegex.test(jobData.from_phone)) {
      throw new Error(`Invalid from_phone format: ${jobData.from_phone}`)
    }

    if (!phoneRegex.test(jobData.to_phone)) {
      throw new Error(`Invalid to_phone format: ${jobData.to_phone}`)
    }
  }

  /**
   * Enqueue multiple shipping jobs
   */
  async enqueueMultipleShippingOrders(ordersData: CreateOrderType[]): Promise<void> {
    this.logger.log(`[SHIPPING_PRODUCER] Enqueue ${ordersData.length} shipping jobs`)

    const results = await Promise.allSettled(ordersData.map((orderData) => this.enqueueCreateOrder(orderData)))

    const successful = results.filter((result) => result.status === 'fulfilled').length
    const failed = results.filter((result) => result.status === 'rejected').length

    this.logger.log(`[SHIPPING_PRODUCER] Results: ${successful} successful, ${failed} failed`)

    if (failed > 0) {
      results.forEach((result, index) => {
        if (result.status === 'rejected') {
          this.logger.error(`[SHIPPING_PRODUCER] Failed job ${index}: ${result.reason}`)
        }
      })
      throw new Error(`Failed to enqueue ${failed} shipping jobs`)
    }
  }

  /**
   * Enqueue GHN webhook processing job
   */
  async enqueueWebhookProcessing(payload: GHNWebhookPayloadType) {
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
      this.logger.error(`[SHIPPING_PRODUCER] Webhook enqueue failed: ${error.message}`)
      throw error
    }
  }
}
