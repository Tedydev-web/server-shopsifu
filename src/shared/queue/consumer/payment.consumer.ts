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
    this.logger.log(`[PAYMENT_CONSUMER] Processing job: ${job.id} - ${job.name}`)
    this.logger.log(`[PAYMENT_CONSUMER] Job data: ${JSON.stringify(job.data, null, 2)}`)

    try {
      switch (job.name) {
        case CANCEL_PAYMENT_JOB_NAME: {
          const { paymentId } = job.data
          this.logger.log(`[PAYMENT_CONSUMER] Cancelling payment: ${paymentId}`)

          const result = await this.sharedPaymentRepo.cancelPaymentAndOrder(paymentId)
          this.logger.log(`[PAYMENT_CONSUMER] Payment cancelled successfully: ${paymentId}`)
          this.logger.log(`[PAYMENT_CONSUMER] Result: ${JSON.stringify(result, null, 2)}`)

          return { message: 'Payment cancelled successfully', paymentId }
        }
        default: {
          this.logger.error(`[PAYMENT_CONSUMER] Unknown job type: ${job.name}`)
          throw new Error(`Unknown job type: ${job.name}`)
        }
      }
    } catch (error) {
      this.logger.error(`[PAYMENT_CONSUMER] Job failed: ${job.id} - ${error.message}`, error.stack)
      throw error
    }
  }

  /**
   * Xử lý khi job bắt đầu
   */
  async onActive(job: Job): Promise<void> {
    this.logger.log(`[PAYMENT_CONSUMER] Job ${job.id} started processing`)
    this.logger.log(`[PAYMENT_CONSUMER] Job name: ${job.name}, data: ${JSON.stringify(job.data, null, 2)}`)
  }

  /**
   * Xử lý khi job hoàn thành
   */
  async onCompleted(job: Job): Promise<void> {
    this.logger.log(`[PAYMENT_CONSUMER] Job ${job.id} completed successfully`)
    this.logger.log(`[PAYMENT_CONSUMER] Job name: ${job.name}, result: ${JSON.stringify(job.returnvalue, null, 2)}`)
  }

  /**
   * Xử lý khi job thất bại
   */
  async onFailed(job: Job, err: Error): Promise<void> {
    this.logger.error(`[PAYMENT_CONSUMER] Job ${job.id} failed:`, err)
    this.logger.error(`[PAYMENT_CONSUMER] Job name: ${job.name}, error: ${err.message}`)
    this.logger.error(`[PAYMENT_CONSUMER] Error stack: ${err.stack}`)
  }
}
