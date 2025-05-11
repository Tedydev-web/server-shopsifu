import { HttpException, HttpStatus } from '@nestjs/common'
import { z } from 'zod'

/**
 * Định dạng chuẩn cho response lỗi đơn lẻ
 */
export const ErrorItemSchema = z.object({
  message: z.string().describe('Thông báo lỗi dạng khóa cho frontend dịch'),
  path: z.string().optional().describe('Đường dẫn tới trường có lỗi'),
  errorCode: z.string().describe('Mã lỗi dùng cho đa ngôn ngữ')
})

/**
 * Định dạng chuẩn cho response lỗi (nhiều lỗi)
 */
export const ErrorResponseSchema = z.object({
  statusCode: z.number().describe('Mã HTTP status'),
  message: z.string().optional().describe('Thông báo chung'),
  errors: z.array(ErrorItemSchema).optional().describe('Danh sách các lỗi cụ thể'),
  error: z.string().optional().describe('Tên lỗi tổng quát'),
  errorCode: z.string().optional().describe('Mã lỗi chung cho response')
})

export type ErrorItemType = z.infer<typeof ErrorItemSchema>
export type ErrorResponseType = z.infer<typeof ErrorResponseSchema>

/**
 * Factory function để tạo ErrorResponseType chuẩn
 * @param errorCode Mã lỗi chung cho toàn bộ response
 * @param statusCode Mã HTTP status
 * @param message Thông báo lỗi chung cho debugging
 * @param errors Danh sách các lỗi cụ thể
 * @returns Object ErrorResponseType chuẩn
 */
export const createErrorResponse = (
  errorCode: string,
  statusCode: HttpStatus = HttpStatus.BAD_REQUEST,
  message?: string,
  errors?: ErrorItemType[]
): ErrorResponseType => {
  return {
    statusCode,
    message,
    errorCode,
    errors
  }
}

/**
 * Factory function để tạo HttpException tuân thủ chuẩn ErrorResponseType
 * @param errorCode Mã lỗi chung
 * @param statusCode Mã HTTP status
 * @param message Thông báo lỗi chung (debugging)
 * @param errors Danh sách các lỗi cụ thể
 * @returns HttpException với response tuân thủ ErrorResponseType
 */
export const createErrorException = (
  errorCode: string,
  statusCode: HttpStatus = HttpStatus.BAD_REQUEST,
  message?: string,
  errors?: ErrorItemType[]
): HttpException => {
  return new HttpException(createErrorResponse(errorCode, statusCode, message, errors), statusCode)
}
