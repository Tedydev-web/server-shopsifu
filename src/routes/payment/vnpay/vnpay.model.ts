import { z } from 'zod'
import { VnpLocale, VnpCurrCode, ProductCode, VnpCardType } from 'vnpay'

// ================== SCHEMA TẠO URL THANH TOÁN ==================
export const CreateVNPayPaymentBodySchema = z.object({
  amount: z.number(),
  orderInfo: z.string(),
  orderId: z.string(),
  returnUrl: z.string().optional().default('https://shopsifu.live/checkout/payment-success'),
  ipnUrl: z.string().optional(),
  locale: z.nativeEnum(VnpLocale).default(VnpLocale.VN),
  currency: z.nativeEnum(VnpCurrCode).default(VnpCurrCode.VND),
  bankCode: z.string().optional(),
  orderType: z.nativeEnum(ProductCode).default(ProductCode.Other),
  ipAddr: z.string().default('127.0.0.1')
})

export const CreateVNPayPaymentResSchema = z.object({
  message: z.string(),
  data: z.object({
    paymentUrl: z.string()
  })
})

// ================== SCHEMA DANH SÁCH NGÂN HÀNG ==================
export const VNPayBankListResSchema = z.object({
  message: z.string(),
  data: z.array(
    z.object({
      bankCode: z.string(),
      bankName: z.string(),
      bankLogo: z.string(),
      bankType: z.number(),
      displayOrder: z.number()
    })
  )
})

// ================== SCHEMA XÁC THỰC URL TRẢ VỀ ==================
export const VNPayReturnUrlSchema = z.object({
  vnp_TmnCode: z.string(),
  vnp_Amount: z.string(),
  vnp_BankCode: z.string().optional(),
  vnp_BankTranNo: z.string().optional(),
  vnp_CardType: z.nativeEnum(VnpCardType).optional(),
  vnp_OrderInfo: z.string(),
  vnp_PayDate: z.string(),
  vnp_ResponseCode: z.string(),
  vnp_TxnRef: z.string(),
  vnp_TransactionNo: z.string(),
  vnp_TransactionStatus: z.string(),
  vnp_SecureHash: z.string(),
  vnp_SecureHashType: z.string().optional()
})

export const VNPayVerifyResSchema = z.object({
  message: z.string(),
  data: z.object({
    isSuccess: z.boolean(),
    isVerified: z.boolean(),
    message: z.string(),
    vnp_Amount: z.number(),
    vnp_TxnRef: z.string(),
    vnp_TransactionNo: z.string(),
    vnp_ResponseCode: z.string(),
    vnp_TransactionStatus: z.string()
  })
})

// ================== SCHEMA TRUY VẤN KẾT QUẢ THANH TOÁN ==================
export const VNPayQueryDrBodySchema = z.object({
  orderId: z.string(),
  orderInfo: z.string(),
  requestId: z.string(),
  transactionDate: z.number(),
  transactionNo: z.number(),
  ipAddr: z.string().default('127.0.0.1'),
  createDate: z.number()
})

export const VNPayQueryDrResSchema = z.object({
  message: z.string(),
  data: z.object({
    isSuccess: z.boolean(),
    isVerified: z.boolean(),
    message: z.string(),
    vnp_Amount: z.number(),
    vnp_TxnRef: z.string(),
    vnp_TransactionNo: z.string().optional(),
    vnp_ResponseCode: z.string(),
    vnp_TransactionStatus: z.string()
  })
})

// ================== SCHEMA HOÀN TIỀN ==================
export const VNPayRefundBodySchema = z.object({
  orderId: z.string(),
  orderInfo: z.string(),
  amount: z.number(),
  requestId: z.string(),
  transactionNo: z.number(),
  ipAddr: z.string().default('127.0.0.1'),
  createBy: z.string()
})

export const VNPayRefundResSchema = z.object({
  message: z.string(),
  data: z.object({
    isSuccess: z.boolean(),
    isVerified: z.boolean(),
    message: z.string(),
    vnp_Amount: z.number(),
    vnp_TxnRef: z.string(),
    vnp_TransactionNo: z.string(),
    vnp_ResponseCode: z.string(),
    vnp_TransactionStatus: z.string()
  })
})

// ================== TYPES EXPORT ==================
export type CreateVNPayPaymentBodyType = z.infer<typeof CreateVNPayPaymentBodySchema>
export type CreateVNPayPaymentResType = z.infer<typeof CreateVNPayPaymentResSchema>
export type VNPayBankListResType = z.infer<typeof VNPayBankListResSchema>
export type VNPayReturnUrlType = z.infer<typeof VNPayReturnUrlSchema>
export type VNPayVerifyResType = z.infer<typeof VNPayVerifyResSchema>
export type VNPayQueryDrBodyType = z.infer<typeof VNPayQueryDrBodySchema>
export type VNPayQueryDrResType = z.infer<typeof VNPayQueryDrResSchema>
export type VNPayRefundBodyType = z.infer<typeof VNPayRefundBodySchema>
export type VNPayRefundResType = z.infer<typeof VNPayRefundResSchema>
