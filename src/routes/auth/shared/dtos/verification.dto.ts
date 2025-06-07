import { createZodDto } from 'nestjs-zod'
import { z } from 'zod'

/**
 * Schema cho các phản hồi yêu cầu xác thực bổ sung.
 */
export const VerificationNeededResponseSchema = z.object({
  verificationType: z.enum(['OTP', '2FA']).describe('Loại xác thực cần thiết (OTP hoặc 2FA).')
})

/**
 * DTO cho các phản hồi yêu cầu xác thực bổ sung.
 * Được sử dụng khi một hành động yêu cầu người dùng phải thực hiện thêm một bước xác thực.
 */
export class VerificationNeededResponseDto extends createZodDto(VerificationNeededResponseSchema) {}
