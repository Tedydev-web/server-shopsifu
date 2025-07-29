import { createZodDto } from 'nestjs-zod'
import {
  CreateVNPayPaymentBodySchema,
  CreateVNPayPaymentResSchema,
  VNPayBankListResSchema,
  VNPayReturnUrlSchema,
  VNPayVerifyResSchema,
  VNPayQueryDrBodySchema,
  VNPayQueryDrResSchema,
  VNPayRefundBodySchema,
  VNPayRefundResSchema
} from './vnpay.model'

// ===== DTOs CHO TẠO URL THANH TOÁN =====
export class CreateVNPayPaymentBodyDTO extends createZodDto(CreateVNPayPaymentBodySchema) {}

export class CreateVNPayPaymentResDTO extends createZodDto(CreateVNPayPaymentResSchema) {}

// ===== DTOs CHO DANH SÁCH NGÂN HÀNG =====
export class VNPayBankListResDTO extends createZodDto(VNPayBankListResSchema) {}

// ===== DTOs CHO XÁC THỰC URL TRẢ VỀ =====
export class VNPayReturnUrlDTO extends createZodDto(VNPayReturnUrlSchema) {}

export class VNPayVerifyResDTO extends createZodDto(VNPayVerifyResSchema) {}

// ===== DTOs CHO TRUY VẤN KẾT QUẢ THANH TOÁN =====
export class VNPayQueryDrBodyDTO extends createZodDto(VNPayQueryDrBodySchema) {}

export class VNPayQueryDrResDTO extends createZodDto(VNPayQueryDrResSchema) {}

// ===== DTOs CHO HOÀN TIỀN =====
export class VNPayRefundBodyDTO extends createZodDto(VNPayRefundBodySchema) {}

export class VNPayRefundResDTO extends createZodDto(VNPayRefundResSchema) {}
