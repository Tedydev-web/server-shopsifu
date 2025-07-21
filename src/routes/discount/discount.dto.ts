import { createZodDto } from 'nestjs-zod'
import {
  CreateDiscountBodySchema,
  GetManageDiscountsQuerySchema,
  GetDiscountDetailResSchema,
  GetDiscountParamsSchema,
  GetDiscountsQuerySchema,
  GetDiscountsResSchema,
  UpdateDiscountBodySchema,
  UpdateDiscountResSchema,
  VerifyDiscountBodySchema,
  GetAvailableDiscountsResSchema,
  VerifyDiscountResSchema
} from './discount.model'

export class GetDiscountsResDTO extends createZodDto(GetDiscountsResSchema) {}

export class GetDiscountsQueryDTO extends createZodDto(GetDiscountsQuerySchema) {}

export class GetAvailableDiscountsResDTO extends createZodDto(GetAvailableDiscountsResSchema) {}

export class GetManageDiscountsQueryDTO extends createZodDto(GetManageDiscountsQuerySchema) {}

export class GetDiscountParamsDTO extends createZodDto(GetDiscountParamsSchema) {}

export class GetDiscountDetailResDTO extends createZodDto(GetDiscountDetailResSchema) {}

export class CreateDiscountBodyDTO extends createZodDto(CreateDiscountBodySchema) {}

export class UpdateDiscountBodyDTO extends createZodDto(UpdateDiscountBodySchema) {}

export class UpdateDiscountResDTO extends createZodDto(UpdateDiscountResSchema) {}

export class VerifyDiscountBodyDTO extends createZodDto(VerifyDiscountBodySchema) {}

export class VerifyDiscountResDTO extends createZodDto(VerifyDiscountResSchema) {}
