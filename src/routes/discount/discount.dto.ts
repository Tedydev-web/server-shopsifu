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
  GetAvailableDiscountsBodySchema,
  GetAvailableDiscountsResSchema
} from 'src/routes/discount/discount.model'
import { DiscountSchema } from 'src/shared/models/shared-discount.model'

export class DiscountDTO extends createZodDto(DiscountSchema) {}

export class GetDiscountsResDTO extends createZodDto(GetDiscountsResSchema) {}

export class GetDiscountsQueryDTO extends createZodDto(GetDiscountsQuerySchema) {}

export class GetManageDiscountsQueryDTO extends createZodDto(GetManageDiscountsQuerySchema) {}

export class GetDiscountParamsDTO extends createZodDto(GetDiscountParamsSchema) {}

export class GetDiscountDetailResDTO extends createZodDto(GetDiscountDetailResSchema) {}

export class CreateDiscountBodyDTO extends createZodDto(CreateDiscountBodySchema) {}

export class UpdateDiscountBodyDTO extends createZodDto(UpdateDiscountBodySchema) {}

export class UpdateDiscountResDTO extends createZodDto(UpdateDiscountResSchema) {}

export class GetAvailableDiscountsBodyDTO extends createZodDto(GetAvailableDiscountsBodySchema) {}

export class GetAvailableDiscountsResDTO extends createZodDto(GetAvailableDiscountsResSchema) {}
