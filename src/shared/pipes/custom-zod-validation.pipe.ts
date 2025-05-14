import { UnprocessableEntityException } from '@nestjs/common'
import { createZodValidationPipe } from 'nestjs-zod'
import { ZodError } from 'zod'

const CustomZodValidationPipe = createZodValidationPipe({
  // provide custom validation exception factory
  createValidationException: (error: ZodError) => {
    console.log('Validation Error:', error.errors)
    return new UnprocessableEntityException(
      error.errors.map((err) => {
        return {
          message: err.message, // Sử dụng key đã chuẩn hóa, ví dụ: ERROR.INVALID_EMAIL
          path: err.path.join('.'),
          params: err.code === 'custom' && err.params ? err.params : {}
        }
      })
    )
  }
})

export default CustomZodValidationPipe
