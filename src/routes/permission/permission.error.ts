import { GlobalError } from 'src/shared/global.error'

export const PermissionError = {
  NotFound: GlobalError.NotFound('permission.error.NOT_FOUND'),

  AlreadyExists: GlobalError.Conflict('permission.error.ALREADY_EXISTS', [
    {
      path: 'path',
      message: 'permission.error.ALREADY_EXISTS',
    },
    {
      path: 'method',
      message: 'permission.error.ALREADY_EXISTS',
    },
  ]),
} as const

export type PermissionErrorKey = keyof typeof PermissionError
