import { createZodDto } from 'nestjs-zod'
import {
  CreateVNPayPaymentUrlSchema,
  VNPayReturnUrlSchema,
  VNPayIpnSchema,
  CreateVNPayPaymentUrlResSchema
} from 'src/routes/payment/vnpay/vnpay.model'

export class CreateVNPayPaymentUrlDTO extends createZodDto(CreateVNPayPaymentUrlSchema) {}
export class VNPayReturnUrlDTO extends createZodDto(VNPayReturnUrlSchema) {}
export class VNPayIpnDTO extends createZodDto(VNPayIpnSchema) {}
export class CreateVNPayPaymentUrlResDTO extends createZodDto(CreateVNPayPaymentUrlResSchema) {}
