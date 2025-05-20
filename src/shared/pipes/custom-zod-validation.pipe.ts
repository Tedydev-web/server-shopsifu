import { UnprocessableEntityException } from '@nestjs/common'
import { createZodValidationPipe } from 'nestjs-zod'
import { ZodError } from 'zod'

const CustomZodValidationPipe = createZodValidationPipe({
  createValidationException: (error: ZodError) => {
    return new UnprocessableEntityException(
      error.errors.map((validationError) => {
        return {
          ...validationError,
          path: validationError.path.join('.')
        }
      })
    )
  }
})

export default CustomZodValidationPipe
