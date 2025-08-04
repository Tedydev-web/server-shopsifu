import { createZodDto } from 'nestjs-zod'
import {
  GetAvailableDiscountsQuerySchema,
  GetAvailableDiscountsResSchema,
  ValidateVoucherCodeBodySchema,
  ValidateVoucherCodeResSchema,
  GetManageDiscountsQuerySchema,
  GetManageDiscountsResSchema,
  GetDiscountParamsSchema,
  GetDiscountDetailResSchema,
  CreateDiscountBodySchema,
  UpdateDiscountBodySchema,
  CreateDiscountResSchema,
  UpdateDiscountResSchema
} from './discount.model'
import { DiscountSchema } from 'src/shared/models/shared-discount.model'

// Base DTO
export class DiscountDTO extends createZodDto(DiscountSchema) {}

// Client DTOs - cho UI checkout
export class GetAvailableDiscountsQueryDTO extends createZodDto(GetAvailableDiscountsQuerySchema) {}

export class GetAvailableDiscountsResDTO extends createZodDto(GetAvailableDiscountsResSchema) {}

export class ValidateVoucherCodeBodyDTO extends createZodDto(ValidateVoucherCodeBodySchema) {}

export class ValidateVoucherCodeResDTO extends createZodDto(ValidateVoucherCodeResSchema) {}

// Admin Management DTOs
export class GetManageDiscountsQueryDTO extends createZodDto(GetManageDiscountsQuerySchema) {}

export class GetManageDiscountsResDTO extends createZodDto(GetManageDiscountsResSchema) {}

export class GetDiscountParamsDTO extends createZodDto(GetDiscountParamsSchema) {}

export class GetDiscountDetailResDTO extends createZodDto(GetDiscountDetailResSchema) {}

export class CreateDiscountBodyDTO extends createZodDto(CreateDiscountBodySchema) {}

export class UpdateDiscountBodyDTO extends createZodDto(UpdateDiscountBodySchema) {}

export class CreateDiscountResDTO extends createZodDto(CreateDiscountResSchema) {}

export class UpdateDiscountResDTO extends createZodDto(UpdateDiscountResSchema) {}
