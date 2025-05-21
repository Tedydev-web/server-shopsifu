import { z } from 'zod'
import { InvalidLanguageFormatException } from './language.error'
import { BasePaginationQuerySchema, createPaginatedResponseSchema } from 'src/shared/models/pagination.model'

const LANGUAGE_ID_REGEX = /^[a-z]{2}(-[A-Z]{2})?$/

export const LanguageSchema = z.object({
  id: z
    .string()
    .max(10)
    .refine((val) => LANGUAGE_ID_REGEX.test(val), {
      message: InvalidLanguageFormatException.message
    }),
  name: z.string().min(1).max(500),
  createdById: z.number().nullable(),
  updatedById: z.number().nullable(),
  deletedAt: z.date().nullable(),
  createdAt: z.date(),
  updatedAt: z.date()
})

export const GetLanguagesResSchema = createPaginatedResponseSchema(LanguageSchema)

export const GetLanguageParamsSchema = z
  .object({
    languageId: z
      .string()
      .max(10)
      .refine((val) => LANGUAGE_ID_REGEX.test(val), {
        message: InvalidLanguageFormatException.message
      })
  })
  .strict()

export const GetLanguagesQuerySchema = BasePaginationQuerySchema.extend({
  sortBy: z.enum(['id', 'name', 'createdAt', 'updatedAt']).optional().default('id'),
  includeDeleted: z.coerce.boolean().optional().default(false),
  startDate: z.string().optional(),
  endDate: z.string().optional(),
  all: z.coerce.boolean().optional().default(false)
}).strict()

export const GetLanguageDetailResSchema = LanguageSchema

export const CreateLanguageBodySchema = LanguageSchema.pick({
  id: true,
  name: true
}).strict()

export const UpdateLanguageBodySchema = LanguageSchema.pick({
  name: true
}).strict()

export const RestoreLanguageBodySchema = z.object({}).strict()

export type LanguageType = z.infer<typeof LanguageSchema>
export type GetLanguagesResType = z.infer<typeof GetLanguagesResSchema>
export type GetLanguageDetailResType = z.infer<typeof GetLanguageDetailResSchema>
export type CreateLanguageBodyType = z.infer<typeof CreateLanguageBodySchema>
export type GetLanguageParamsType = z.infer<typeof GetLanguageParamsSchema>
export type UpdateLanguageBodyType = z.infer<typeof UpdateLanguageBodySchema>
export type GetLanguagesQueryType = z.infer<typeof GetLanguagesQuerySchema>
export type RestoreLanguageBodyType = z.infer<typeof RestoreLanguageBodySchema>
