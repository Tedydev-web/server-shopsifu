import { HttpStatus } from '@nestjs/common'
import { ApiException } from 'src/shared/exceptions/api.exception'

export const RoleError = {
  NOT_FOUND: new ApiException(HttpStatus.NOT_FOUND, 'E0501', 'role.error.NOT_FOUND'),
  ALREADY_EXISTS: new ApiException(HttpStatus.CONFLICT, 'E0502', 'role.error.ALREADY_EXISTS'),
  NAME_TOO_LONG: new ApiException(HttpStatus.BAD_REQUEST, 'E0503', 'role.error.NAME_TOO_LONG'),
  DESCRIPTION_TOO_LONG: new ApiException(HttpStatus.BAD_REQUEST, 'E0504', 'role.error.DESCRIPTION_TOO_LONG'),
  INVALID_PERMISSION_IDS: new ApiException(HttpStatus.BAD_REQUEST, 'E0505', 'role.error.INVALID_PERMISSION_IDS'),
  PERMISSION_NOT_FOUND: new ApiException(HttpStatus.BAD_REQUEST, 'E0506', 'role.error.PERMISSION_NOT_FOUND'),
  ROLE_IN_USE: new ApiException(HttpStatus.CONFLICT, 'E0507', 'role.error.ROLE_IN_USE'),
  CANNOT_DELETE_DEFAULT_ROLE: new ApiException(HttpStatus.FORBIDDEN, 'E0508', 'role.error.CANNOT_DELETE_DEFAULT_ROLE'),
  INVALID_IMPORT_DATA: new ApiException(HttpStatus.BAD_REQUEST, 'E0509', 'role.error.INVALID_IMPORT_DATA'),
  IMPORT_FAILED: new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'E0510', 'role.error.IMPORT_FAILED'),
  EXPORT_FAILED: new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'E0511', 'role.error.EXPORT_FAILED'),
  DELETED_PERMISSION_INCLUDED: new ApiException(HttpStatus.BAD_REQUEST, 'E0512', 'role.error.DELETED_PERMISSION_INCLUDED'),
} as const

export type RoleErrorKey = keyof typeof RoleError
