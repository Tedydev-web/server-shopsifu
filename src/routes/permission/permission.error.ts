import { HttpStatus } from '@nestjs/common'
import { ApiException } from 'src/shared/exceptions/api.exception'

export const PermissionError = {
  NOT_FOUND: new ApiException(HttpStatus.NOT_FOUND, 'E0401', 'permission.error.NOT_FOUND'),
  ALREADY_EXISTS: new ApiException(HttpStatus.CONFLICT, 'E0402', 'permission.error.ALREADY_EXISTS'),
  INVALID_METHOD: new ApiException(HttpStatus.BAD_REQUEST, 'E0403', 'permission.error.INVALID_METHOD'),
  INVALID_PATH: new ApiException(HttpStatus.BAD_REQUEST, 'E0404', 'permission.error.INVALID_PATH'),
  NAME_TOO_LONG: new ApiException(HttpStatus.BAD_REQUEST, 'E0405', 'permission.error.NAME_TOO_LONG'),
  DESCRIPTION_TOO_LONG: new ApiException(HttpStatus.BAD_REQUEST, 'E0406', 'permission.error.DESCRIPTION_TOO_LONG'),
  PATH_TOO_LONG: new ApiException(HttpStatus.BAD_REQUEST, 'E0407', 'permission.error.PATH_TOO_LONG'),
  INVALID_IMPORT_DATA: new ApiException(HttpStatus.BAD_REQUEST, 'E0408', 'permission.error.INVALID_IMPORT_DATA'),
  IMPORT_FAILED: new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'E0409', 'permission.error.IMPORT_FAILED'),
  EXPORT_FAILED: new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'E0410', 'permission.error.EXPORT_FAILED'),
} as const

export type PermissionErrorKey = keyof typeof PermissionError
