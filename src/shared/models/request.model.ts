import { z } from 'zod'

export const EmptyBodySchema = z.object({}).strict()

export type EmptyBodyType = z.infer<typeof EmptyBodySchema>
