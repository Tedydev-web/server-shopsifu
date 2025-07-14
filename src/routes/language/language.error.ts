import { UnprocessableEntityException } from '@nestjs/common'

export const LanguageAlreadyExistsException = new UnprocessableEntityException([
  {
    message: 'Error.LanguageAlreadyExists',
    path: 'id',
  },
])
