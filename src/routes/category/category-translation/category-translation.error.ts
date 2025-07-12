import { UnprocessableEntityException } from '@nestjs/common'

export const CategoryTranslationAlreadyExistsException = new UnprocessableEntityException([
  {
    path: 'languageId',
    message: 'Error.CategoryTranslationAlreadyExists',
  },
])
