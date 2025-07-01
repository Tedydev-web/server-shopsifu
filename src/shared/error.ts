import { NotFoundException, UnprocessableEntityException } from '@nestjs/common'

export const NotFoundRecordException = new NotFoundException('Error.NotFound')

export const InvalidPasswordException = new UnprocessableEntityException([
  {
    message: 'Error.InvalidPassword',
    path: 'password',
  },
])
