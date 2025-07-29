import { Injectable } from '@nestjs/common'
import { SepayConfig } from 'src/shared/constants/payment.constant'
import { PREFIX_PAYMENT_CODE } from 'src/shared/constants/other.constant'

@Injectable()
export class SepayQRService {
  /**
   * Tạo QR code URL cho Sepay payment
   * @param paymentId - ID của payment
   * @param amount - Số tiền cần thanh toán
   * @returns URL của QR code
   */
  generateQRCode(paymentId: string, amount: number): string {
    const paymentCode = `${PREFIX_PAYMENT_CODE}${paymentId}`

    // Tạo query string theo cấu trúc Sepay
    const queryString = new URLSearchParams({
      acc: SepayConfig.DEFAULT_ACCOUNT,
      bank: SepayConfig.DEFAULT_BANK,
      amount: amount.toString(),
      des: paymentCode
    }).toString()

    return `${SepayConfig.QR_BASE_URL}?${queryString}`
  }
}
