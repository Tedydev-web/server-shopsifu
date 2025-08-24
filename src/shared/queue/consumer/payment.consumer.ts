import { Processor, WorkerHost } from '@nestjs/bullmq'
import { Injectable, Logger } from '@nestjs/common'
import { Job } from 'bullmq'
import { CANCEL_PAYMENT_JOB_NAME, PAYMENT_QUEUE_NAME } from 'src/shared/constants/queue.constant'
import { SharedPaymentRepository } from 'src/shared/repositories/shared-payment.repo'

@Injectable()
@Processor(PAYMENT_QUEUE_NAME)
export class PaymentConsumer extends WorkerHost {
  private readonly logger = new Logger(PaymentConsumer.name)

  constructor(private readonly sharedPaymentRepo: SharedPaymentRepository) {
    super()
  }

  async process(job: Job<{ paymentId: number }, any, string>): Promise<any> {
    try {
      switch (job.name) {
        case CANCEL_PAYMENT_JOB_NAME: {
          const { paymentId } = job.data

          await this.sharedPaymentRepo.cancelPaymentAndOrder(paymentId)

          return { message: 'Payment cancelled successfully', paymentId }
        }
        default: {
          this.logger.error(`[PAYMENT_CONSUMER] Unknown job type: ${job.name}`)
          throw new Error(`Unknown job type: ${job.name}`)
        }
      }
    } catch (error) {
      throw error
    }
  }
}
