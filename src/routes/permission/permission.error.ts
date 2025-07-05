import { UnprocessableEntityException } from '@nestjs/common'

export const PermissionAlreadyExistsException = new UnprocessableEntityException([
  {
    message: 'permission.error.ALREADY_EXISTS',
    path: 'path',
  },
  {
    message: 'permission.error.ALREADY_EXISTS',
    path: 'method',
  },
])
