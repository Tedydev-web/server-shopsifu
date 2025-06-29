import { HttpStatus } from '@nestjs/common'
import { ApiException } from './exceptions/api.exception'

/**
 * Provides static methods for creating common API exceptions.
 * Follows HTTP status code conventions for consistent error handling.
 */
export class GlobalError {
  public static BadRequest(message: string = 'global.error.BAD_REQUEST', details?: any): ApiException {
    return new ApiException(HttpStatus.BAD_REQUEST, 'E0002', message, details)
  }

  public static Unauthorized(message: string = 'global.error.UNAUTHORIZED', details?: any): ApiException {
    return new ApiException(HttpStatus.UNAUTHORIZED, 'E0003', message, details)
  }

  public static Forbidden(message: string = 'global.error.FORBIDDEN', details?: any): ApiException {
    return new ApiException(HttpStatus.FORBIDDEN, 'E0004', message, details)
  }

  public static NotFound(message: string = 'global.error.NOT_FOUND', details?: any): ApiException {
    return new ApiException(HttpStatus.NOT_FOUND, 'E0005', message, details)
  }

  public static Conflict(message: string = 'global.error.CONFLICT', details?: any): ApiException {
    return new ApiException(HttpStatus.CONFLICT, 'E0007', message, details)
  }

  public static UnprocessableEntity(
    message: string = 'global.error.UNPROCESSABLE_ENTITY',
    details?: any,
  ): ApiException {
    return new ApiException(HttpStatus.UNPROCESSABLE_ENTITY, 'E0006', message, details)
  }

  public static InternalServerError(
    message: string = 'global.error.INTERNAL_SERVER_ERROR',
    details?: any,
  ): ApiException {
    return new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'E0001', message, details)
  }

  public static TooManyRequests(message: string = 'global.error.TOO_MANY_REQUESTS', details?: any): ApiException {
    return new ApiException(HttpStatus.TOO_MANY_REQUESTS, 'E0008', message, details)
  }

  public static ServiceUnavailable(message: string = 'global.error.SERVICE_UNAVAILABLE', details?: any): ApiException {
    return new ApiException(HttpStatus.SERVICE_UNAVAILABLE, 'E0009', message, details)
  }

  public static RequestTimeout(message: string = 'global.error.REQUEST_TIMEOUT', details?: any): ApiException {
    return new ApiException(HttpStatus.REQUEST_TIMEOUT, 'E0010', message, details)
  }

  public static Gone(message: string = 'global.error.GONE', details?: any): ApiException {
    return new ApiException(HttpStatus.GONE, 'E0011', message, details)
  }

  public static MethodNotAllowed(message: string = 'global.error.METHOD_NOT_ALLOWED', details?: any): ApiException {
    return new ApiException(HttpStatus.METHOD_NOT_ALLOWED, 'E0012', message, details)
  }

  public static NotAcceptable(message: string = 'global.error.NOT_ACCEPTABLE', details?: any): ApiException {
    return new ApiException(HttpStatus.NOT_ACCEPTABLE, 'E0013', message, details)
  }

  public static UnsupportedMediaType(
    message: string = 'global.error.UNSUPPORTED_MEDIA_TYPE',
    details?: any,
  ): ApiException {
    return new ApiException(HttpStatus.UNSUPPORTED_MEDIA_TYPE, 'E0014', message, details)
  }

  public static NotFoundRecord(message: string = 'global.error.NOT_FOUND_RECORD', details?: any): ApiException {
    return new ApiException(HttpStatus.NOT_FOUND, 'E0015', message, details)
  }

  public static InvalidPassword(message: string = 'global.error.INVALID_PASSWORD', details?: any): ApiException {
    return new ApiException(HttpStatus.BAD_REQUEST, 'E0016', message, details)
  }

  public static NotFoundRecordException(
    message: string = 'global.error.NOT_FOUND_RECORD',
    details?: any,
  ): ApiException {
    return new ApiException(HttpStatus.NOT_FOUND, 'E0015', message, details)
  }

  public static InvalidPasswordException(
    message: string = 'global.error.INVALID_PASSWORD',
    details?: any,
  ): ApiException {
    return new ApiException(HttpStatus.BAD_REQUEST, 'E0016', message, details)
  }

  public static VersionConflict(message: string = 'global.error.VERSION_CONFLICT', details?: any): ApiException {
    return new ApiException(HttpStatus.CONFLICT, 'E0017', message, details)
  }
}
