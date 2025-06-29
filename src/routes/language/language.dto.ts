import { createZodDto } from 'nestjs-zod'
import {
  CreateLanguageBodySchema,
  GetLanguageDetailResSchema,
  GetLanguageParamsSchema,
  GetLanguagesResSchema,
  UpdateLanguageBodySchema,
  CreateLanguageResSchema,
  UpdateLanguageResSchema,
  DeleteLanguageResSchema,
  LanguagePaginationQuerySchema,
} from 'src/routes/language/language.model'

// Request DTOs
export class GetLanguageParamsDTO extends createZodDto(GetLanguageParamsSchema) {}
export class CreateLanguageBodyDTO extends createZodDto(CreateLanguageBodySchema) {}
export class UpdateLanguageBodyDTO extends createZodDto(UpdateLanguageBodySchema) {}
export class LanguagePaginationQueryDTO extends createZodDto(LanguagePaginationQuerySchema) {}

// Response DTOs
export class GetLanguagesResDTO extends createZodDto(GetLanguagesResSchema) {}
export class GetLanguageDetailResDTO extends createZodDto(GetLanguageDetailResSchema) {}
export class CreateLanguageResDTO extends createZodDto(CreateLanguageResSchema) {}
export class UpdateLanguageResDTO extends createZodDto(UpdateLanguageResSchema) {}
export class DeleteLanguageResDTO extends createZodDto(DeleteLanguageResSchema) {}
