import { UnprocessableEntityException, BadRequestException } from '@nestjs/common'

export const CategoryTranslationAlreadyExistsException = new UnprocessableEntityException([
  {
    path: 'languageId',
    message: 'category.category-translation.error.ALREADY_EXISTS',
  },
])

export const CategoryTranslationLanguageNotFoundException = new BadRequestException([
  {
    path: 'languageId',
    message: 'category.category-translation.error.LANGUAGE_NOT_FOUND',
  },
])

export const CategoryTranslationCategoryNotFoundException = new BadRequestException([
  {
    path: 'categoryId',
    message: 'category.category-translation.error.CATEGORY_NOT_FOUND',
  },
])
