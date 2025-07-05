import { UnprocessableEntityException } from '@nestjs/common'

export const CategoryTranslationAlreadyExistsException = new UnprocessableEntityException([
  {
    path: 'languageId',
    message: 'category.category-translation.error.ALREADY_EXISTS',
  },
])
