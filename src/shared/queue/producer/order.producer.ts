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
    this.logger.log(`[ORDER_PRODUCER] Bắt đầu thêm cancel payment job cho paymentId: ${paymentId}`)

    try {
      const jobId = generateCancelPaymentJobId(paymentId)
      this.logger.log(`[ORDER_PRODUCER] Generated job ID: ${jobId}`)

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

      this.logger.log(`[ORDER_PRODUCER] Cancel payment job added successfully: ${job.id}`)
      this.logger.log(`[ORDER_PRODUCER] Job details: name=${job.name}, data=${JSON.stringify(job.data, null, 2)}`)
      return job
    } catch (error) {
      this.logger.error(`[ORDER_PRODUCER] Failed to add cancel payment job: ${error.message}`, error.stack)
      throw error
    }
  }
}
