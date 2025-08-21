import { InjectQueue } from '@nestjs/bullmq'
import { Injectable } from '@nestjs/common'
import { Queue } from 'bullmq'
import { CREATE_SHIPPING_ORDER_JOB, SHIPPING_QUEUE_NAME } from 'src/shared/constants/queue.constant'
import { CreateOrderType } from 'src/routes/shipping/shipping.model'

@Injectable()
export class ShippingProducer {
  constructor(@InjectQueue(SHIPPING_QUEUE_NAME) private shippingQueue: Queue) {}

  async enqueueCreateOrder(jobData: CreateOrderType) {
    return this.shippingQueue.add(CREATE_SHIPPING_ORDER_JOB, jobData, {
      removeOnComplete: true,
      removeOnFail: true,
      attempts: 3,
      backoff: { type: 'exponential', delay: 2000 }
    })
  }
}
