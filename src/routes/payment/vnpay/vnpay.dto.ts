import { createZodDto } from 'nestjs-zod'
import {
  CreateVNPayPaymentBodySchema,
  CreateVNPayPaymentResSchema,
  VNPayBankListResSchema,
  VNPayReturnUrlSchema,
  VNPayVerifyResSchema
} from './vnpay.model'

export class CreateVNPayPaymentBodyDTO extends createZodDto(CreateVNPayPaymentBodySchema) {}

export class CreateVNPayPaymentResDTO extends createZodDto(CreateVNPayPaymentResSchema) {}

export class VNPayBankListResDTO extends createZodDto(VNPayBankListResSchema) {}

export class VNPayReturnUrlDTO extends createZodDto(VNPayReturnUrlSchema) {}

export class VNPayVerifyResDTO extends createZodDto(VNPayVerifyResSchema) {}
