import { UnprocessableEntityException } from '@nestjs/common'

export const PermissionAlreadyExistsException = new UnprocessableEntityException([
  {
    message: 'Error.PermissionAlreadyExists',
    path: 'path',
  },
  {
    message: 'Error.PermissionAlreadyExists',
    path: 'method',
  },
])
