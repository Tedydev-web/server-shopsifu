import { createZodDto } from 'nestjs-zod'
import {
  CreateLanguageBodySchema,
  GetLanguageDetailResSchema,
  GetLanguageParamsSchema,
  GetLanguageResShema,
  UpdateLanguageBodySchema
} from './language.model'

export class GetLanguageResDTO extends createZodDto(GetLanguageResShema) {}
export class GetLanguageParamsDTO extends createZodDto(GetLanguageParamsSchema) {}
export class GetLanguageDetailResDTO extends createZodDto(GetLanguageDetailResSchema) {}
export class CreateLanguageBodyDTO extends createZodDto(CreateLanguageBodySchema) {}
export class UpdateLanguageBodyDTO extends createZodDto(UpdateLanguageBodySchema) {}
