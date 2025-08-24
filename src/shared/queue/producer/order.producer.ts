import { InjectQueue } from '@nestjs/bullmq'
import { Injectable } from '@nestjs/common'
import { Queue } from 'bullmq'
import { CANCEL_PAYMENT_JOB_NAME, PAYMENT_QUEUE_NAME } from 'src/shared/constants/queue.constant'
import { generateCancelPaymentJobId } from 'src/shared/helpers'

@Injectable()
export class OrderProducer {
  constructor(@InjectQueue(PAYMENT_QUEUE_NAME) private paymentQueue: Queue) {}

  async addCancelPaymentJob(paymentId: number) {
    try {
      const jobId = generateCancelPaymentJobId(paymentId)

      const job = await this.paymentQueue.add(
        CANCEL_PAYMENT_JOB_NAME,
        {
          paymentId
        },
        {
          delay: 1000 * 60 * 15, // delay 15 phút
          jobId: jobId,
          removeOnComplete: true,
          removeOnFail: true
        }
      )

      return job
    } catch (error) {
      throw error
    }
  }
}
