import { UnprocessableEntityException } from '@nestjs/common'

export const ProductTranslationAlreadyExistsException = new UnprocessableEntityException([
  {
    path: 'productId',
    message: 'Error.ProductTranslationAlreadyExists',
  },
])
