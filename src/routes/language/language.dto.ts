import { createZodDto } from 'nestjs-zod'
import {
  CreateLanguageBodySchema,
  GetLanguageDetailResSchema,
  GetLanguageParamsSchema,
  GetLanguagesQuerySchema,
  GetLanguagesResSchema,
  RestoreLanguageBodySchema,
  UpdateLanguageBodySchema
} from 'src/routes/language/language.model'

export class GetLanguagesResDTO extends createZodDto(GetLanguagesResSchema) {}

export class GetLanguageParamsDTO extends createZodDto(GetLanguageParamsSchema) {}

export class GetLanguagesQueryDTO extends createZodDto(GetLanguagesQuerySchema) {}

export class GetLanguageDetailResDTO extends createZodDto(GetLanguageDetailResSchema) {}

export class CreateLanguageBodyDTO extends createZodDto(CreateLanguageBodySchema) {}

export class UpdateLanguageBodyDTO extends createZodDto(UpdateLanguageBodySchema) {}

export class RestoreLanguageBodyDTO extends createZodDto(RestoreLanguageBodySchema) {}
