import { Module } from '@nestjs/common'
import { VnpayModule } from 'nestjs-vnpay'
import { ignoreLogger } from 'vnpay'
import { VNPayService } from './vnpay.service'
import { VNPayController } from './vnpay.controller'
import { ConfigModule, ConfigService } from '@nestjs/config'
import { BullModule } from '@nestjs/bullmq'
import { PAYMENT_QUEUE_NAME } from 'src/shared/constants/queue.constant'
import { VNPayRepo } from 'src/routes/payment/vnpay/vnpay.repo'

@Module({
  imports: [
    BullModule.registerQueue({
      name: PAYMENT_QUEUE_NAME
    }),
    VnpayModule.registerAsync({
      imports: [ConfigModule],
      useFactory: async (configService: ConfigService) => ({
        secureSecret: configService.getOrThrow<string>('payment.vnpay.secureSecret'),
        tmnCode: configService.getOrThrow<string>('payment.vnpay.tmnCode'),
        loggerFn: ignoreLogger
      }),
      inject: [ConfigService]
    })
  ],
  providers: [VNPayService, VNPayRepo],
  controllers: [VNPayController]
})
export class VNPayModule {}
