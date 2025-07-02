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

// --- Common Exception Instances ---
export const NotFoundRecordException = new NotFoundException([{ message: 'global.error.NOT_FOUND' }])
export const InvalidPasswordException = (i18n: I18nService<I18nTranslations>) =>
  new UnprocessableEntityException([{ message: i18n.t('global.error.INVALID_PASSWORD'), path: 'password' }])

// --- Factory Functions for Custom Error ---
export const NotFoundError = (message = 'global.error.NOT_FOUND_RECORD', path?: string) =>
  new NotFoundException([{ message, ...(path ? { path } : {}) }])

export const BadRequestError = (message = 'global.error.BAD_REQUEST', path?: string) =>
  new BadRequestException([{ message, ...(path ? { path } : {}) }])

export const UnauthorizedError = (message = 'global.error.UNAUTHORIZED', path?: string) =>
  new UnauthorizedException([{ message, ...(path ? { path } : {}) }])

export const ForbiddenError = (message = 'global.error.FORBIDDEN', path?: string) =>
  new ForbiddenException([{ message, ...(path ? { path } : {}) }])

export const ConflictError = (message = 'global.error.CONFLICT', path?: string) =>
  new ConflictException([{ message, ...(path ? { path } : {}) }])

export const UnprocessableEntityError = (message = 'global.error.UNPROCESSABLE_ENTITY', path?: string) =>
  new UnprocessableEntityException([{ message, ...(path ? { path } : {}) }])

export const InternalServerError = (message = 'global.error.INTERNAL_SERVER_ERROR', path?: string) =>
  new InternalServerErrorException([{ message, ...(path ? { path } : {}) }])

export const ServiceUnavailableError = (message = 'global.error.SERVICE_UNAVAILABLE', path?: string) =>
  new ServiceUnavailableException([{ message, ...(path ? { path } : {}) }])

export const RequestTimeoutError = (message = 'global.error.REQUEST_TIMEOUT', path?: string) =>
  new RequestTimeoutException([{ message, ...(path ? { path } : {}) }])

export const GoneError = (message = 'global.error.GONE', path?: string) =>
  new GoneException([{ message, ...(path ? { path } : {}) }])

export const MethodNotAllowedError = (message = 'global.error.METHOD_NOT_ALLOWED', path?: string) =>
  new MethodNotAllowedException([{ message, ...(path ? { path } : {}) }])

export const NotAcceptableError = (message = 'global.error.NOT_ACCEPTABLE', path?: string) =>
  new NotAcceptableException([{ message, ...(path ? { path } : {}) }])

export const UnsupportedMediaTypeError = (message = 'global.error.UNSUPPORTED_MEDIA_TYPE', path?: string) =>
  new UnsupportedMediaTypeException([{ message, ...(path ? { path } : {}) }])
