import { Processor, WorkerHost } from '@nestjs/bullmq'
import { Job } from 'bullmq'
import { CANCEL_PAYMENT_JOB_NAME, PAYMENT_QUEUE_NAME } from 'src/shared/constants/queue.constant'
import { SharedPaymentRepository } from 'src/shared/repositories/shared-payment.repo'

@Processor(PAYMENT_QUEUE_NAME)
export class PaymentConsumer extends WorkerHost {
  constructor(private readonly sharedPaymentRepo: SharedPaymentRepository) {
    super()
  }
  async process(job: Job<{ paymentId: number }, any, string>): Promise<any> {
    switch (job.name) {
      case CANCEL_PAYMENT_JOB_NAME: {
        const { paymentId } = job.data
        await this.sharedPaymentRepo.cancelPaymentAndOrder(paymentId)
        return {}
      }
      default: {
        break
      }
    }
  }
}
