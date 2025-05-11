import { z } from 'zod'

export const EmptyBodySchema = z.object({})

export type EmptyBodyType = z.infer<typeof EmptyBodySchema>
