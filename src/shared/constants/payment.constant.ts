export const PaymentStatus = {
  PENDING: 'PENDING',
  SUCCESS: 'SUCCESS',
  FAILED: 'FAILED'
} as const
export type PaymentStatus = (typeof PaymentStatus)[keyof typeof PaymentStatus]

export const PaymentGateway = {
  SEPAY: 'sepay',
  VNPAY: 'vnpay'
} as const
export type PaymentGateway = (typeof PaymentGateway)[keyof typeof PaymentGateway]

export const VNPayLocale = {
  VN: 'vn',
  EN: 'en'
} as const
export type VNPayLocale = (typeof VNPayLocale)[keyof typeof VNPayLocale]

export const VNPayProductCode = {
  OTHER: 'other',
  TOPUP: 'topup',
  BILLPAY: 'billpay',
  FASHION: 'fashion',
  ELECTRONIC: 'electronic',
  THUTIENNHANH: 'thutiennhanh',
  VNPAYQR: 'vnpayqr',
  VNPAYQRMOMO: 'vnpayqrmomo',
  VNPAYQRMSQR: 'vnpayqrmsqr',
  VNPAYQRCITI: 'vnpayqrciti'
} as const
export type VNPayProductCode = (typeof VNPayProductCode)[keyof typeof VNPayProductCode]

export const SepayConfig = {
  QR_BASE_URL: 'https://qr.sepay.vn/img',
  DEFAULT_BANK: 'TPBank',
  DEFAULT_ACCOUNT: process.env.SEPAY_ACCOUNT || '00869685621'
} as const
