import { Module } from '@nestjs/common'
import { VnpayModule } from 'nestjs-vnpay'
import { HashAlgorithm, ignoreLogger } from 'vnpay'
import { VNPayService } from './vnpay.service'
import { VNPayController } from './vnpay.controller'

@Module({
  imports: [
    VnpayModule.register({
      tmnCode: 'E12E8KYJ',
      secureSecret: 'VMZQECLOHDPXFBHLHMHYDLYIANSIHGQM',
      vnpayHost: 'https://sandbox.vnpayment.vn',

      // Cấu hình tùy chọn
      testMode: true, // Chế độ test (ghi đè vnpayHost thành sandbox nếu là true)
      hashAlgorithm: HashAlgorithm.SHA512, // Thuật toán mã hóa
      enableLog: true, // Bật/tắt ghi log
      loggerFn: ignoreLogger // Hàm xử lý log tùy chỉnh
    })
  ],
  providers: [VNPayService],
  controllers: [VNPayController]
})
export class VNPayModule {}
