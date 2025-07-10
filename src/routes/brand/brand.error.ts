import { UnprocessableEntityException } from '@nestjs/common'

export const BrandAlreadyExistsException = new UnprocessableEntityException([
  {
    message: 'brand.brand.error.ALREADY_EXISTS',
    path: 'name'
  }
])
