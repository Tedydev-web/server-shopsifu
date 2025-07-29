import { Module } from '@nestjs/common'
import { VnpayModule } from 'nestjs-vnpay'
import { ignoreLogger } from 'vnpay'
import { VNPayService } from './vnpay.service'
import { VNPayController } from './vnpay.controller'
import { ConfigModule, ConfigService } from '@nestjs/config'

@Module({
  imports: [
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
  providers: [VNPayService],
  controllers: [VNPayController]
})
export class VNPayModule {}
