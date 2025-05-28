import { z } from 'zod'
import { createZodDto } from 'nestjs-zod'

export const PendingLinkDetailsResSchema = z.object({
  existingUserEmail: z.string().email(),
  googleEmail: z.string().email(),
  googleName: z.string().optional().nullable(),
  googleAvatar: z.string().url().optional().nullable(),
  message: z.string().optional()
})

export class PendingLinkDetailsResDto extends createZodDto(PendingLinkDetailsResSchema) {}
