import { createZodDto } from 'nestjs-zod'
import { z } from 'zod'

/**
 * Schema cơ bản cho một response thành công.
 * Mọi response thành công từ API nên tuân theo cấu trúc này.
 */
export const BaseSuccessResponseSchema = z.object({
  success: z.literal(true).default(true),
  statusCode: z.number().int().positive(),
  message: z.string(),
  data: z.any().optional().nullable()
})

/**
 * Schema cho response thành công có chứa dữ liệu phân trang.
 */
export const PaginatedResponseSchema = BaseSuccessResponseSchema.extend({
  metadata: z
    .object({
      totalItems: z.number().int(),
      currentPage: z.number().int(),
      itemsPerPage: z.number().int(),
      totalPages: z.number().int()
    })
    .optional()
})

/**
 * Schema cho một response chỉ chứa thông điệp (thường dùng cho các request POST, PATCH, DELETE thành công).
 * Kế thừa từ BaseSuccessResponseSchema để đảm bảo tính nhất quán.
 */
export const MessageResSchema = BaseSuccessResponseSchema.pick({
  message: true
})

/**
 * Schema cơ bản cho một response lỗi.
 * Mọi response lỗi từ API nên tuân theo cấu trúc này.
 */
export const ErrorResponseSchema = z.object({
  success: z.literal(false).default(false),
  statusCode: z.number().int(),
  error: z.string(), // Mã lỗi máy có thể đọc (machine-readable error code)
  message: z.string(), // Thông báo lỗi cho người dùng (human-readable, đã được dịch)
  details: z.any().optional().nullable() // Chi tiết lỗi (ví dụ: lỗi validation)
})

// ===================================================================================
// DTO Classes - Sử dụng trong các controller để định nghĩa kiểu trả về với Swagger
// ===================================================================================

export class BaseSuccessResponseDto extends createZodDto(BaseSuccessResponseSchema) {}
export class PaginatedResponseDto extends createZodDto(PaginatedResponseSchema) {}
export class MessageResDTO extends createZodDto(MessageResSchema) {}
export class ErrorResponseDto extends createZodDto(ErrorResponseSchema) {}
