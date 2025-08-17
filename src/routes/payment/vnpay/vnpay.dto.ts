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

export class CreateVNPayPaymentBodyDTO extends createZodDto(CreateVNPayPaymentBodySchema) {}

export class CreateVNPayPaymentResDTO extends createZodDto(CreateVNPayPaymentResSchema) {}

export class VNPayBankListResDTO extends createZodDto(VNPayBankListResSchema) {}

export class VNPayReturnUrlDTO extends createZodDto(VNPayReturnUrlSchema) {}

export class VNPayVerifyResDTO extends createZodDto(VNPayVerifyResSchema) {}

export class VNPayQueryDrBodyDTO extends createZodDto(VNPayQueryDrBodySchema) {}

export class VNPayQueryDrResDTO extends createZodDto(VNPayQueryDrResSchema) {}

export class VNPayRefundBodyDTO extends createZodDto(VNPayRefundBodySchema) {}

export class VNPayRefundResDTO extends createZodDto(VNPayRefundResSchema) {}
