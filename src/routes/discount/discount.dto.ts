import { createZodDto } from 'nestjs-zod'
import {
  CreateDiscountBodySchema,
  GetDiscountDetailResSchema,
  GetDiscountParamsSchema,
  GetDiscountsQuerySchema,
  GetDiscountsResSchema,
  UpdateDiscountBodySchema
} from './discount.model'

export class GetDiscountParamsDTO extends createZodDto(GetDiscountParamsSchema) {}
export class GetDiscountsQueryDTO extends createZodDto(GetDiscountsQuerySchema) {}
export class GetDiscountDetailResDTO extends createZodDto(GetDiscountDetailResSchema) {}
export class GetDiscountsResDTO extends createZodDto(GetDiscountsResSchema) {}
export class CreateDiscountBodyDTO extends createZodDto(CreateDiscountBodySchema) {}
export class UpdateDiscountBodyDTO extends createZodDto(UpdateDiscountBodySchema) {}
