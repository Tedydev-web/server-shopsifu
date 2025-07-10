import { UnprocessableEntityException, NotFoundException } from '@nestjs/common'

export const BrandTranslationAlreadyExistsException = new UnprocessableEntityException([
  {
    path: 'languageId',
    message: 'brand.brandTranslation.error.ALREADY_EXISTS'
  }
])

export const BrandTranslationBrandNotFoundException = new NotFoundException([
  {
    path: 'brandId',
    message: 'brand.brandTranslation.error.BRAND_NOT_FOUND'
  }
])

export const BrandTranslationLanguageNotFoundException = new NotFoundException([
  {
    path: 'languageId',
    message: 'brand.brandTranslation.error.LANGUAGE_NOT_FOUND'
  }
])
