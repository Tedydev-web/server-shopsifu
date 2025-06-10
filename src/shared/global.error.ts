import { HttpStatus } from '@nestjs/common'
import { ApiException } from './exceptions/api.exception'

export class GlobalError {
  public static InternalServerError(message?: string, details?: any): ApiException {
    return new ApiException(
      HttpStatus.INTERNAL_SERVER_ERROR,
      'ERROR_INTERNAL_SERVER',
      message || 'global.error.general.internalServerError',
      details
    )
  }

  public static BadRequest(message?: string, details?: any): ApiException {
    return new ApiException(
      HttpStatus.BAD_REQUEST,
      'ERROR_BAD_REQUEST',
      message || 'global.error.http.badRequest',
      details
    )
  }

  public static Unauthorized(message?: string, details?: any): ApiException {
    return new ApiException(
      HttpStatus.UNAUTHORIZED,
      'ERROR_UNAUTHORIZED',
      message || 'global.error.http.unauthorized',
      details
    )
  }

  public static Forbidden(message?: string, details?: any): ApiException {
    return new ApiException(HttpStatus.FORBIDDEN, 'ERROR_FORBIDDEN', message || 'global.error.http.forbidden', details)
  }

  public static NotFound(entity: string = 'resource', details?: any): ApiException {
    const i18nKey = `global.error.notFound.${entity}`
    return new ApiException(HttpStatus.NOT_FOUND, 'ERROR_NOT_FOUND', i18nKey, details)
  }
}
