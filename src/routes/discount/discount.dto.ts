import { createZodDto } from 'nestjs-zod'
import {
  GetAvailableDiscountsQuerySchema,
  GetAvailableDiscountsResSchema,
  VerifyDiscountBodySchema,
  VerifyDiscountResSchema,
  GetDiscountParamsSchema,
  GetDiscountDetailResSchema,
  GetManageDiscountsQuerySchema,
  GetDiscountsResSchema,
  CreateDiscountBodySchema,
  UpdateDiscountBodySchema
} from './discount.model'

export class GetAvailableDiscountsQueryDTO extends createZodDto(GetAvailableDiscountsQuerySchema) {}
export class GetAvailableDiscountsResDTO extends createZodDto(GetAvailableDiscountsResSchema) {}
export class VerifyDiscountBodyDTO extends createZodDto(VerifyDiscountBodySchema) {}
export class VerifyDiscountResDTO extends createZodDto(VerifyDiscountResSchema) {}
export class GetDiscountParamsDTO extends createZodDto(GetDiscountParamsSchema) {}
export class GetDiscountDetailResDTO extends createZodDto(GetDiscountDetailResSchema) {}
export class GetManageDiscountsQueryDTO extends createZodDto(GetManageDiscountsQuerySchema) {}
export class GetDiscountsResDTO extends createZodDto(GetDiscountsResSchema) {}
export class CreateDiscountBodyDTO extends createZodDto(CreateDiscountBodySchema) {}
export class UpdateDiscountBodyDTO extends createZodDto(UpdateDiscountBodySchema) {}
