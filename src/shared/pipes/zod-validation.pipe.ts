import {
  Injectable,
  PipeTransform,
  ArgumentMetadata,
  BadRequestException,
  UnprocessableEntityException
} from '@nestjs/common'
import { ZodSchema, ZodError } from 'zod'
import { createZodValidationPipe } from 'nestjs-zod'

/**
 * Xử lý và định dạng lỗi Zod thành dạng nhất quán
 */
const formatZodError = (error: ZodError) => {
  return error.errors.map((err) => ({
    message: err.message,
    path: err.path.join('.'),
    code: err.code
  }))
}

/**
 * Pipe để xác thực dữ liệu đầu vào sử dụng Zod schema
 * Chuyển đổi lỗi Zod thành UnprocessableEntityException
 */
@Injectable()
export class ZodValidationPipe implements PipeTransform {
  constructor(private schema: ZodSchema) {}

  transform(value: any, metadata: ArgumentMetadata) {
    try {
      // Chuẩn hóa và xác thực dữ liệu đầu vào
      return this.schema.parse(value)
    } catch (error) {
      if (error instanceof ZodError) {
        throw new UnprocessableEntityException(formatZodError(error))
      }
      throw new BadRequestException('Validation failed')
    }
  }
}

/**
 * Custom validation pipe sử dụng nestjs-zod
 * Sử dụng khi cần một global pipe hoặc khi làm việc với các decorator của nestjs-zod
 */
export const CustomZodValidationPipe = createZodValidationPipe({
  createValidationException: (error: ZodError) => {
    return new UnprocessableEntityException(formatZodError(error))
  }
})
