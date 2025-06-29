import { z } from 'zod'
import {
  createTypedSuccessResponseSchema,
  createTypedPaginatedResponseSchema,
  MessageResSchema,
} from 'src/shared/models/response.model'
import { BasePaginationQuerySchema, PaginatedResponseType } from 'src/shared/models/pagination.model'

export const LanguageSchema = z.object({
  id: z.string().max(10),
  name: z.string().max(500),
  createdById: z.number().nullable(),
  updatedById: z.number().nullable(),
  deletedAt: z.date().nullable(),
  createdAt: z.date(),
  updatedAt: z.date(),
})

// Response Schemas
export const GetLanguagesResSchema = createTypedPaginatedResponseSchema(LanguageSchema)
export const GetLanguageDetailResSchema = createTypedSuccessResponseSchema(LanguageSchema)
export const CreateLanguageResSchema = createTypedSuccessResponseSchema(LanguageSchema)
export const UpdateLanguageResSchema = createTypedSuccessResponseSchema(LanguageSchema)
export const DeleteLanguageResSchema = MessageResSchema

// Request Schemas
export const GetLanguageParamsSchema = z
  .object({
    languageId: z.string().max(10),
  })
  .strict()

export const CreateLanguageBodySchema = LanguageSchema.pick({
  id: true,
  name: true,
}).strict()

export const UpdateLanguageBodySchema = LanguageSchema.pick({
  name: true,
}).strict()

// Pagination Schema (re-export for module-specific customization if needed)
export const LanguagePaginationQuerySchema = BasePaginationQuerySchema

// Types
export type LanguageType = z.infer<typeof LanguageSchema>
export type GetLanguagesResType = z.infer<typeof GetLanguagesResSchema>
export type GetLanguageDetailResType = z.infer<typeof GetLanguageDetailResSchema>
export type CreateLanguageResType = z.infer<typeof CreateLanguageResSchema>
export type UpdateLanguageResType = z.infer<typeof UpdateLanguageResSchema>
export type DeleteLanguageResType = z.infer<typeof DeleteLanguageResSchema>
export type CreateLanguageBodyType = z.infer<typeof CreateLanguageBodySchema>
export type GetLanguageParamsType = z.infer<typeof GetLanguageParamsSchema>
export type UpdateLanguageBodyType = z.infer<typeof UpdateLanguageBodySchema>

// Pagination Types (re-export for module use)
export type LanguagePaginationQueryType = z.infer<typeof LanguagePaginationQuerySchema>

// Re-export PaginatedResponseType for module use
export type { PaginatedResponseType }
