import { HttpStatus } from '@nestjs/common'
import { ApiException } from 'src/shared/exceptions/api.exception'

function createApiError(
  status: HttpStatus,
  errorType: string,
  errorCode: string,
  fieldPath?: string,
  args?: Record<string, any>
) {
  return new ApiException(status, errorType, errorCode, [{ code: errorCode, path: fieldPath, args }])
}

export const LanguageAlreadyExistsException = createApiError(
  HttpStatus.CONFLICT,
  'ResourceConflict',
  'Error.Language.AlreadyExists',
  'id'
)

export const LanguageNotFoundException = (languageId: string) =>
  createApiError(HttpStatus.NOT_FOUND, 'ResourceNotFound', 'Error.Language.NotFound', 'languageId', { id: languageId })

export const LanguageDeletedException = (languageId: string) =>
  createApiError(HttpStatus.GONE, 'ResourceDeleted', 'Error.Language.Deleted', 'languageId', { id: languageId })

export const LanguageInUseException = (languageId: string) =>
  createApiError(HttpStatus.CONFLICT, 'ResourceInUse', 'Error.Language.InUse', 'languageId', { id: languageId })

export const InvalidLanguageFormatException = createApiError(
  HttpStatus.UNPROCESSABLE_ENTITY,
  'ValidationError',
  'Error.Language.InvalidFormat',
  'id'
)

export const LanguageActionForbiddenException = createApiError(
  HttpStatus.FORBIDDEN,
  'Forbidden',
  'Error.Language.ActionForbidden'
)
