import { UnprocessableEntityException } from '@nestjs/common'

export const ProductTranslationAlreadyExistsException = new UnprocessableEntityException([
  {
    path: 'productId',
    message: 'product.product-translation.error.ALREADY_EXISTS',
  },
])
