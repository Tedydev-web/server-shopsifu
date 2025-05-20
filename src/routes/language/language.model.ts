import { z } from 'zod'
import { InvalidLanguageFormatException } from './language.error'

// Regex để kiểm tra định dạng language ID (ví dụ: 'en', 'vi', 'en-US')
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

export const GetLanguagesResSchema = z.object({
  data: z.array(LanguageSchema),
  totalItems: z.number(),
  page: z.number().optional(),
  limit: z.number().optional(),
  totalPages: z.number().optional()
})

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

// Schema cho query params để filtering, sorting và pagination
export const GetLanguagesQuerySchema = z
  .object({
    page: z.coerce.number().int().positive().optional().default(1),
    limit: z.coerce.number().int().positive().max(100).optional().default(10),
    sortBy: z.enum(['id', 'name', 'createdAt', 'updatedAt']).optional().default('id'),
    sortOrder: z.enum(['asc', 'desc']).optional().default('asc'),
    search: z.string().optional(),
    includeDeleted: z.coerce.boolean().optional().default(false)
  })
  .strict()

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
