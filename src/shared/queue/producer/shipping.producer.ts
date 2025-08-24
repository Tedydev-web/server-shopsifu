import { InjectQueue } from '@nestjs/bullmq'
import { Injectable, Logger } from '@nestjs/common'
import { Queue } from 'bullmq'
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
    return this.shippingQueue.add(CREATE_SHIPPING_ORDER_JOB, jobData, {
      attempts: 3,
      backoff: { type: 'exponential', delay: 2000 },
      removeOnComplete: true,
      removeOnFail: true
    })
  }

  /**
   * Enqueue GHN webhook processing job
   */
  async enqueueWebhookProcessing(payload: GHNWebhookPayloadType) {
    return this.shippingQueue.add(
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
  }
}
