import { createZodDto } from 'nestjs-zod'
import { z } from 'zod'

export const MessageResSchema = z.object({
  message: z.string()
})

export class MessageResDTO extends createZodDto(MessageResSchema) {}
