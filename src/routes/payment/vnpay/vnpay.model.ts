import { z } from 'zod'
import { VNPayLocale, VNPayProductCode } from 'src/shared/constants/payment.constant'

export const CreateVNPayPaymentUrlSchema = z.object({
  vnp_Amount: z.number(),
  vnp_IpAddr: z.string(),
  vnp_TxnRef: z.string(),
  vnp_OrderInfo: z.string(),
  vnp_OrderType: z.nativeEnum(VNPayProductCode).default(VNPayProductCode.OTHER),
  vnp_ReturnUrl: z.string(),
  vnp_Locale: z.nativeEnum(VNPayLocale).default(VNPayLocale.VN),
  vnp_BankCode: z.string().optional()
})

export const CreateVNPayPaymentUrlResSchema = z.object({
  paymentUrl: z.string().url()
})

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

export const VNPayIpnSchema = z.object({
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

export type CreateVNPayPaymentUrlType = z.infer<typeof CreateVNPayPaymentUrlSchema>
export type CreateVNPayPaymentUrlResType = z.infer<typeof CreateVNPayPaymentUrlResSchema>
export type VNPayReturnUrlType = z.infer<typeof VNPayReturnUrlSchema>
export type VNPayIpnType = z.infer<typeof VNPayIpnSchema>
