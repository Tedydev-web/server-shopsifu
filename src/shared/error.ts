import {
  NotFoundException,
  UnprocessableEntityException,
  BadRequestException,
  UnauthorizedException,
  ForbiddenException,
  ConflictException,
  InternalServerErrorException,
  ServiceUnavailableException,
  RequestTimeoutException,
  GoneException,
  MethodNotAllowedException,
  NotAcceptableException,
  UnsupportedMediaTypeException,
} from '@nestjs/common'
import { I18nService } from 'nestjs-i18n'
import { I18nTranslations } from 'src/generated/i18n.generated'

// --- Exception Factory với Translation tích hợp ---
class ExceptionFactory {
  private static i18n: I18nService<I18nTranslations>

  static setI18n(i18n: I18nService<I18nTranslations>) {
    ExceptionFactory.i18n = i18n
  }

  private static t(key: string, args?: Record<string, any>): string {
    return this.i18n?.t(key as any, { args }) || key
  }

  // --- Common Exceptions ---
  static notFound(message = 'global.error.NOT_FOUND', path?: string) {
    return new NotFoundException([{ message: this.t(message), ...(path ? { path } : {}) }])
  }

  static badRequest(message = 'global.error.BAD_REQUEST', path?: string) {
    return new BadRequestException([{ message: this.t(message), ...(path ? { path } : {}) }])
  }

  static unauthorized(message = 'global.error.UNAUTHORIZED', path?: string) {
    return new UnauthorizedException([{ message: this.t(message), ...(path ? { path } : {}) }])
  }

  static forbidden(message = 'global.error.FORBIDDEN', path?: string) {
    return new ForbiddenException([{ message: this.t(message), ...(path ? { path } : {}) }])
  }

  static conflict(message = 'global.error.CONFLICT', path?: string) {
    return new ConflictException([{ message: this.t(message), ...(path ? { path } : {}) }])
  }

  static unprocessableEntity(message = 'global.error.UNPROCESSABLE_ENTITY', path?: string) {
    return new UnprocessableEntityException([{ message: this.t(message), ...(path ? { path } : {}) }])
  }

  static internalServerError(message = 'global.error.INTERNAL_SERVER_ERROR', path?: string) {
    return new InternalServerErrorException([{ message: this.t(message), ...(path ? { path } : {}) }])
  }

  static serviceUnavailable(message = 'global.error.SERVICE_UNAVAILABLE', path?: string) {
    return new ServiceUnavailableException([{ message: this.t(message), ...(path ? { path } : {}) }])
  }

  static requestTimeout(message = 'global.error.REQUEST_TIMEOUT', path?: string) {
    return new RequestTimeoutException([{ message: this.t(message), ...(path ? { path } : {}) }])
  }

  static gone(message = 'global.error.GONE', path?: string) {
    return new GoneException([{ message: this.t(message), ...(path ? { path } : {}) }])
  }

  static methodNotAllowed(message = 'global.error.METHOD_NOT_ALLOWED', path?: string) {
    return new MethodNotAllowedException([{ message: this.t(message), ...(path ? { path } : {}) }])
  }

  static notAcceptable(message = 'global.error.NOT_ACCEPTABLE', path?: string) {
    return new NotAcceptableException([{ message: this.t(message), ...(path ? { path } : {}) }])
  }

  static unsupportedMediaType(message = 'global.error.UNSUPPORTED_MEDIA_TYPE', path?: string) {
    return new UnsupportedMediaTypeException([{ message: this.t(message), ...(path ? { path } : {}) }])
  }

  // --- Specific Business Exceptions ---
  static invalidPassword() {
    return this.unprocessableEntity('global.error.INVALID_PASSWORD', 'password')
  }

  static recordNotFound(message = 'global.error.NOT_FOUND_RECORD', path?: string) {
    return this.notFound(message, path)
  }

  static alreadyExists(message: string, path?: string) {
    return this.unprocessableEntity(message, path)
  }

  static outOfStock(message = 'cart.error.OUT_OF_STOCK', path?: string) {
    return this.badRequest(message, path)
  }

  static cannotUpdateOrDeleteYourself() {
    return this.forbidden('user.error.CANNOT_UPDATE_OR_DELETE_YOURSELF')
  }

  static cannotUpdateAdminUser() {
    return this.forbidden('user.error.CANNOT_UPDATE_ADMIN_USER')
  }

  static cannotDeleteAdminUser() {
    return this.forbidden('user.error.CANNOT_DELETE_ADMIN_USER')
  }

  static cannotSetAdminRoleToUser() {
    return this.forbidden('user.error.CANNOT_SET_ADMIN_ROLE_TO_USER')
  }

  static prohibitedActionOnBaseRole() {
    return this.forbidden('role.error.PROHIBITED_ACTION_ON_BASE_ROLE')
  }
}

// --- Export ExceptionFactory để sử dụng trong services ---
export { ExceptionFactory }

// --- Legacy exports cho backward compatibility (sẽ deprecated) ---
export const NotFoundRecordException = ExceptionFactory.recordNotFound()
export const InvalidPasswordException = ExceptionFactory.invalidPassword()

// --- Factory Functions cho backward compatibility (sẽ deprecated) ---
export const NotFoundError = (message = 'global.error.NOT_FOUND_RECORD', path?: string) =>
  ExceptionFactory.notFound(message, path)

export const BadRequestError = (message = 'global.error.BAD_REQUEST', path?: string) =>
  ExceptionFactory.badRequest(message, path)

export const UnauthorizedError = (message = 'global.error.UNAUTHORIZED', path?: string) =>
  ExceptionFactory.unauthorized(message, path)

export const ForbiddenError = (message = 'global.error.FORBIDDEN', path?: string) =>
  ExceptionFactory.forbidden(message, path)

export const ConflictError = (message = 'global.error.CONFLICT', path?: string) =>
  ExceptionFactory.conflict(message, path)

export const UnprocessableEntityError = (message = 'global.error.UNPROCESSABLE_ENTITY', path?: string) =>
  ExceptionFactory.unprocessableEntity(message, path)

export const InternalServerError = (message = 'global.error.INTERNAL_SERVER_ERROR', path?: string) =>
  ExceptionFactory.internalServerError(message, path)

export const ServiceUnavailableError = (message = 'global.error.SERVICE_UNAVAILABLE', path?: string) =>
  ExceptionFactory.serviceUnavailable(message, path)

export const RequestTimeoutError = (message = 'global.error.REQUEST_TIMEOUT', path?: string) =>
  ExceptionFactory.requestTimeout(message, path)

export const GoneError = (message = 'global.error.GONE', path?: string) => ExceptionFactory.gone(message, path)

export const MethodNotAllowedError = (message = 'global.error.METHOD_NOT_ALLOWED', path?: string) =>
  ExceptionFactory.methodNotAllowed(message, path)

export const NotAcceptableError = (message = 'global.error.NOT_ACCEPTABLE', path?: string) =>
  ExceptionFactory.notAcceptable(message, path)

export const UnsupportedMediaTypeError = (message = 'global.error.UNSUPPORTED_MEDIA_TYPE', path?: string) =>
  ExceptionFactory.unsupportedMediaType(message, path)
