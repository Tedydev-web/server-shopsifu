import { UnprocessableEntityException } from '@nestjs/common'

export const PermissionAlreadyExistsException = new UnprocessableEntityException([
  {
    message: 'permission.permission.error.ALREADY_EXISTS',
    path: 'path'
  },
  {
    message: 'permission.permission.error.ALREADY_EXISTS',
    path: 'method'
  }
])
