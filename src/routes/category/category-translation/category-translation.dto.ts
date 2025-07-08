import { createZodDto } from 'nestjs-zod'
import {
  CreateCategoryTranslationBodySchema,
  GetCategoryTranslationDetailResSchema,
  GetCategoryTranslationParamsSchema,
  UpdateCategoryTranslationBodySchema,
} from 'src/routes/category/category-translation/category-translation.model'

export class GetCategoryTranslationDetailResDTO extends createZodDto(GetCategoryTranslationDetailResSchema) {}
export class GetCategoryTranslationParamsDTO extends createZodDto(GetCategoryTranslationParamsSchema) {}

export class CreateCategoryTranslationBodyDTO extends createZodDto(CreateCategoryTranslationBodySchema) {}

export class UpdateCategoryTranslationBodyDTO extends createZodDto(UpdateCategoryTranslationBodySchema) {}
