import { z } from 'zod'
import { VnpLocale, VnpCurrCode } from 'vnpay'

// Schema cho việc tạo URL thanh toán VNPay
export const CreateVNPayPaymentBodySchema = z.object({
  amount: z.number().positive('Số tiền phải lớn hơn 0'),
  orderInfo: z.string().min(1, 'Thông tin đơn hàng không được để trống'),
  orderId: z.string().min(1, 'Mã đơn hàng không được để trống'),
  returnUrl: z.string().url('URL trả về không hợp lệ'),
  ipnUrl: z.string().url('URL IPN không hợp lệ').optional(),
  locale: z.nativeEnum(VnpLocale).default(VnpLocale.VN),
  currency: z.nativeEnum(VnpCurrCode).default(VnpCurrCode.VND),
  bankCode: z.string().optional(),
  language: z.nativeEnum(VnpLocale).default(VnpLocale.VN),
  customerEmail: z.string().email('Email không hợp lệ').optional(),
  customerPhone: z.string().optional(),
  customerAddress: z.string().optional(),
  customerName: z.string().optional()
})

export type CreateVNPayPaymentBodyType = z.infer<typeof CreateVNPayPaymentBodySchema>

// Schema cho response tạo URL thanh toán
export const CreateVNPayPaymentResSchema = z.object({
  paymentUrl: z.string().url(),
  orderId: z.string(),
  amount: z.number(),
  orderInfo: z.string()
})

export type CreateVNPayPaymentResType = z.infer<typeof CreateVNPayPaymentResSchema>

// Schema cho danh sách ngân hàng
export const VNPayBankListResSchema = z.object({
  banks: z.array(
    z.object({
      bankCode: z.string(),
      bankName: z.string(),
      bankLogo: z.string().optional()
    })
  )
})

export type VNPayBankListResType = z.infer<typeof VNPayBankListResSchema>

// Schema cho xác thực URL trả về
export const VNPayReturnUrlSchema = z.object({
  vnp_Amount: z.string(),
  vnp_BankCode: z.string().optional(),
  vnp_BankTranNo: z.string().optional(),
  vnp_CardType: z.string().optional(),
  vnp_OrderInfo: z.string(),
  vnp_PayDate: z.string(),
  vnp_ResponseCode: z.string(),
  vnp_TmnCode: z.string(),
  vnp_TransactionNo: z.string(),
  vnp_TransactionStatus: z.string(),
  vnp_TxnRef: z.string(),
  vnp_SecureHash: z.string()
})

export type VNPayReturnUrlType = z.infer<typeof VNPayReturnUrlSchema>

// Schema cho response xác thực
export const VNPayVerifyResSchema = z.object({
  isSuccess: z.boolean(),
  isVerified: z.boolean(),
  message: z.string(),
  data: z.record(z.any()).optional()
})

export type VNPayVerifyResType = z.infer<typeof VNPayVerifyResSchema>
