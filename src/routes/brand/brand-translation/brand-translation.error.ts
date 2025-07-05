import { UnprocessableEntityException } from '@nestjs/common'

export const BrandTranslationAlreadyExistsException = new UnprocessableEntityException([
  {
    path: 'languageId',
    message: 'brand.brand-translation.error.ALREADY_EXISTS',
  },
])
