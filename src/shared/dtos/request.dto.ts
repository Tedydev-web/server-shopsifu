import { createZodDto } from 'nestjs-zod'
import { z } from 'zod'

export const EmptyBodySchema = z.object({})

export class EmptyBodyDTO extends createZodDto(EmptyBodySchema) {}
