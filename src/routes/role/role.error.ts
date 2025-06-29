import { GlobalError } from 'src/shared/global.error'

export const RoleError = {
  NotFound: GlobalError.NotFound('role.error.NOT_FOUND'),

  AlreadyExists: GlobalError.Conflict('role.error.ALREADY_EXISTS', [
    {
      path: 'name',
      message: 'role.error.ALREADY_EXISTS',
    },
  ]),

  DeletedPermissionIncluded: GlobalError.BadRequest('role.error.DELETED_PERMISSION_INCLUDED', [
    {
      path: 'permissions',
      message: 'role.error.DELETED_PERMISSION_INCLUDED',
    },
  ]),

  CannotUpdateDefaultRole: GlobalError.Forbidden('role.error.CANNOT_UPDATE_DEFAULT_ROLE'),

  CannotDeleteDefaultRole: GlobalError.Forbidden('role.error.CANNOT_DELETE_DEFAULT_ROLE'),
} as const

export type RoleErrorKey = keyof typeof RoleError
