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
    this.logger.log(`Processing job: ${job.id} - ${job.name}`)

    try {
      switch (job.name) {
        case CANCEL_PAYMENT_JOB_NAME: {
          const { paymentId } = job.data
          this.logger.log(`Cancelling payment: ${paymentId}`)

          await this.sharedPaymentRepo.cancelPaymentAndOrder(paymentId)

          this.logger.log(`Payment cancelled successfully: ${paymentId}`)
          return { message: 'Payment cancelled successfully', paymentId }
        }
        default: {
          throw new Error(`Unknown job type: ${job.name}`)
        }
      }
    } catch (error) {
      this.logger.error(`Job failed: ${job.id} - ${error.message}`, error.stack)
      throw error
    }
  }

  /**
   * Xử lý khi job bắt đầu
   */
  async onActive(job: Job): Promise<void> {
    this.logger.log(`Job ${job.id} started processing`)
  }

  /**
   * Xử lý khi job hoàn thành
   */
  async onCompleted(job: Job): Promise<void> {
    this.logger.log(`Job ${job.id} completed successfully`)
  }

  /**
   * Xử lý khi job thất bại
   */
  async onFailed(job: Job, err: Error): Promise<void> {
    this.logger.error(`Job ${job.id} failed:`, err)
  }
}
