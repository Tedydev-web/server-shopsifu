import { UnprocessableEntityException } from '@nestjs/common'

export const LanguageAlreadyExistsException = () =>
  new UnprocessableEntityException([
    {
      message: 'language.error.ALREADY_EXISTS',
      path: 'id',
    },
  ])
