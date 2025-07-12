import { createZodDto } from 'nestjs-zod'
import {
  CreateProductTranslationBodySchema,
  GetProductTranslationDetailResSchema,
  GetProductTranslationParamsSchema,
  UpdateProductTranslationBodySchema,
} from 'src/routes/product/product-translation/product-translation.model'

export class GetProductTranslationDetailResDTO extends createZodDto(GetProductTranslationDetailResSchema) {}

export class GetProductTranslationParamsDTO extends createZodDto(GetProductTranslationParamsSchema) {}

export class CreateProductTranslationBodyDTO extends createZodDto(CreateProductTranslationBodySchema) {}

export class UpdateProductTranslationBodyDTO extends createZodDto(UpdateProductTranslationBodySchema) {}
