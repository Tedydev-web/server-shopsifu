import { Module } from '@nestjs/common'
import { VNPayController } from './vnpay.controller'
import { VNPayService } from './vnpay.service'
import { VNPayRepo } from './vnpay.repo'
import { PaymentProducer } from 'src/shared/producers/payment.producer'
import { BullModule } from '@nestjs/bullmq'
import { PAYMENT_QUEUE_NAME } from 'src/shared/constants/queue.constant'

@Module({
  imports: [
    BullModule.registerQueue({
      name: PAYMENT_QUEUE_NAME
    })
  ],
  providers: [VNPayService, VNPayRepo, PaymentProducer],
  controllers: [VNPayController]
})
export class VNPayModule {}
