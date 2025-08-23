import { z } from 'zod'

export const LanguageSchema = z.object({
  id: z.string().max(10),
  name: z.string().max(500),
  createdById: z.string().nullable(),
  updatedById: z.string().nullable(),
  deletedAt: z.union([z.string(), z.date()]).nullable(),
  createdAt: z.union([z.string(), z.date()]),
  updatedAt: z.union([z.string(), z.date()])
})

export const GetLanguagesResSchema = z.object({
  message: z.string().optional(),
  data: z.array(LanguageSchema),
  totalItems: z.number()
})

export const GetLanguageParamsSchema = z
  .object({
    languageId: z.string().max(10)
  })
  .strict()

export const GetLanguageDetailResSchema = z.object({
  message: z.string().optional(),
  data: LanguageSchema
})

export const CreateLanguageBodySchema = LanguageSchema.pick({
  id: true,
  name: true
}).strict()

export const UpdateLanguageBodySchema = LanguageSchema.pick({
  name: true
}).strict()

export type LanguageType = z.infer<typeof LanguageSchema>
export type GetLanguagesResType = z.infer<typeof GetLanguagesResSchema>
export type GetLanguageDetailResType = z.infer<typeof GetLanguageDetailResSchema>
export type CreateLanguageBodyType = z.infer<typeof CreateLanguageBodySchema>
export type GetLanguageParamsType = z.infer<typeof GetLanguageParamsSchema>
export type UpdateLanguageBodyType = z.infer<typeof UpdateLanguageBodySchema>
