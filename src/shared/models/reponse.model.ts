import { z } from 'zod'

export const MessageCodeSchema = z.object({
  code: z.string(),
  params: z.record(z.any()).optional()
})

export const ErrorCodeSchema = z.object({
  code: z.string(),
  path: z.string().optional(),
  params: z.record(z.any()).optional()
})

export const MessageResSchema = z.object({
  message: z.union([z.string(), MessageCodeSchema])
})

export const ResponseMetadataSchema = z.object({
  page: z.number().optional(),
  limit: z.number().optional(),
  total: z.number().optional(),
  totalPages: z.number().optional()
})

export const ApiResponseSchema = z.object({
  success: z.boolean().default(true),
  statusCode: z.number().default(200),
  message: z.union([z.string(), MessageCodeSchema]).optional(),
  errors: z.array(ErrorCodeSchema).optional(),
  data: z.any().optional(),
  meta: ResponseMetadataSchema.optional(),
  timestamp: z
    .string()
    .datetime()
    .default(() => new Date().toISOString()),
  requestId: z.string().uuid().optional()
})

export type MessageResType = z.infer<typeof MessageResSchema>
export type MessageCodeType = z.infer<typeof MessageCodeSchema>
export type ErrorCodeType = z.infer<typeof ErrorCodeSchema>
export type ResponseMetadataType = z.infer<typeof ResponseMetadataSchema>
export type ApiResponseType<T = any> = z.infer<typeof ApiResponseSchema> & { data?: T }
