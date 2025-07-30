import { createZodDto } from 'nestjs-zod'
import {
  GetManageDiscountsQuerySchema,
  GetManageDiscountsResSchema,
  GetDiscountParamsSchema,
  GetDiscountDetailResSchema,
  CreateDiscountBodySchema,
  UpdateDiscountBodySchema,
  CreateDiscountResSchema,
  UpdateDiscountResSchema,
  GetDiscountsQuerySchema,
  GetDiscountsResSchema,
  ValidateDiscountCodeBodySchema,
  ValidateDiscountCodeResSchema
} from './discount.model'
import { DiscountSchema } from 'src/shared/models/shared-discount.model'

export class DiscountDTO extends createZodDto(DiscountSchema) {}

export class GetManageDiscountsQueryDTO extends createZodDto(GetManageDiscountsQuerySchema) {}

export class GetManageDiscountsResDTO extends createZodDto(GetManageDiscountsResSchema) {}

export class GetDiscountParamsDTO extends createZodDto(GetDiscountParamsSchema) {}

export class GetDiscountDetailResDTO extends createZodDto(GetDiscountDetailResSchema) {}

export class CreateDiscountBodyDTO extends createZodDto(CreateDiscountBodySchema) {}

export class UpdateDiscountBodyDTO extends createZodDto(UpdateDiscountBodySchema) {}

export class CreateDiscountResDTO extends createZodDto(CreateDiscountResSchema) {}

export class UpdateDiscountResDTO extends createZodDto(UpdateDiscountResSchema) {}

// Client DTOs
export class GetDiscountsQueryDTO extends createZodDto(GetDiscountsQuerySchema) {}

export class GetDiscountsResDTO extends createZodDto(GetDiscountsResSchema) {}

export class ValidateDiscountCodeBodyDTO extends createZodDto(ValidateDiscountCodeBodySchema) {}

export class ValidateDiscountCodeResDTO extends createZodDto(ValidateDiscountCodeResSchema) {}
