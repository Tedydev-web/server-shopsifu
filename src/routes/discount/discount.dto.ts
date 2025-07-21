import { createZodDto } from 'nestjs-zod'
import {
  DiscountParamsSchema,
  DiscountDetailResSchema,
  DiscountListQuerySchema,
  DiscountListResSchema,
  CreateDiscountBodySchema,
  UpdateDiscountBodySchema,
  VerifyDiscountBodySchema
} from './discount.model'

export class DiscountParamsDTO extends createZodDto(DiscountParamsSchema) {}
export class DiscountDetailResDTO extends createZodDto(DiscountDetailResSchema) {}
export class DiscountListQueryDTO extends createZodDto(DiscountListQuerySchema) {}
export class DiscountListResDTO extends createZodDto(DiscountListResSchema) {}
export class CreateDiscountBodyDTO extends createZodDto(CreateDiscountBodySchema) {}
export class UpdateDiscountBodyDTO extends createZodDto(UpdateDiscountBodySchema) {}
export class VerifyDiscountBodyDTO extends createZodDto(VerifyDiscountBodySchema) {}
