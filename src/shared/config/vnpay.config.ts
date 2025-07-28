import { registerAs } from '@nestjs/config'

export const VNPayConfig = registerAs('vnpay', () => ({
  tmnCode: process.env.VNPAY_TMN_CODE,
  secureSecret: process.env.VNPAY_SECURE_SECRET,
  vnpayHost: process.env.NODE_ENV === 'production' ? 'https://pay.vnpay.vn' : 'https://sandbox.vnpayment.vn',
  queryDrAndRefundHost: process.env.NODE_ENV === 'production' ? 'https://pay.vnpay.vn' : 'https://sandbox.vnpayment.vn',
  testMode: process.env.NODE_ENV !== 'production',
  hashAlgorithm: 'SHA512',
  enableLog: process.env.NODE_ENV !== 'production',
  returnUrl: process.env.VNPAY_RETURN_URL,
  ipnUrl: process.env.VNPAY_IPN_URL,
  paymentUrl: process.env.VNPAY_URL,
  endpoints: {
    paymentEndpoint: 'paymentv2/vpcpay.html',
    queryDrRefundEndpoint: 'merchant_webapi/api/transaction',
    getBankListEndpoint: 'qrpayauth/api/merchant/get_bank_list'
  }
}))
