import { createZodDto } from 'nestjs-zod'
import { z } from 'zod'

export const VerificationNeededResponseSchema = z.object({
  verificationType: z.enum(['OTP', '2FA']).describe('Loại xác thực cần thiết (OTP hoặc 2FA).')
})

export class VerificationNeededResponseDto extends createZodDto(VerificationNeededResponseSchema) {}
