import { UnprocessableEntityException } from '@nestjs/common'

export const BrandNotFoundException = new UnprocessableEntityException([
  {
    path: 'brandId',
    message: 'product.error.BRAND_NOT_FOUND',
  },
])
