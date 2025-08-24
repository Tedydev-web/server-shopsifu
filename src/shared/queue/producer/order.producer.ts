import { InjectQueue } from '@nestjs/bullmq'
import { Injectable, Logger } from '@nestjs/common'
import { Queue } from 'bullmq'
import { CANCEL_PAYMENT_JOB_NAME, PAYMENT_QUEUE_NAME } from 'src/shared/constants/queue.constant'
import { generateCancelPaymentJobId } from 'src/shared/helpers'

@Injectable()
export class OrderProducer {
  private readonly logger = new Logger(OrderProducer.name)

  constructor(@InjectQueue(PAYMENT_QUEUE_NAME) private paymentQueue: Queue) {}

  async addCancelPaymentJob(paymentId: number) {
    try {
      this.logger.log(`Adding cancel payment job for paymentId: ${paymentId}`)

      const job = await this.paymentQueue.add(
        CANCEL_PAYMENT_JOB_NAME,
        {
          paymentId
        },
        {
          delay: 1000 * 60, // delay 1 phút
          jobId: generateCancelPaymentJobId(paymentId),
          removeOnComplete: true,
          removeOnFail: true
        }
      )

      this.logger.log(`Cancel payment job added successfully: ${job.id}`)
      return job
    } catch (error) {
      this.logger.error(`Failed to add cancel payment job: ${error.message}`, error.stack)
      throw error
    }
  }
}
