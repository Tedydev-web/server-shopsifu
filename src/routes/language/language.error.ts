import { HttpStatus } from '@nestjs/common'
import { ApiException } from 'src/shared/exceptions/api.exception'

export const LanguageAlreadyExistsException = new ApiException(
  HttpStatus.CONFLICT,
  'RESOURCE_CONFLICT',
  'Error.Language.AlreadyExists',
  [{ code: 'Error.Language.AlreadyExists', path: 'id' }]
)

export const LanguageNotFoundException = (languageId: string) =>
  new ApiException(HttpStatus.NOT_FOUND, 'RESOURCE_NOT_FOUND', 'Error.Language.NotFound', [
    { code: 'Error.Language.NotFound', path: 'languageId', args: { id: languageId } }
  ])

export const LanguageDeletedException = (languageId: string) =>
  new ApiException(HttpStatus.GONE, 'RESOURCE_DELETED', 'Error.Language.Deleted', [
    { code: 'Error.Language.Deleted', path: 'languageId', args: { id: languageId } }
  ])

export const LanguageInUseException = (languageId: string) =>
  new ApiException(HttpStatus.CONFLICT, 'RESOURCE_IN_USE', 'Error.Language.InUse', [
    { code: 'Error.Language.InUse', path: 'languageId', args: { id: languageId } }
  ])

export const InvalidLanguageFormatException = new ApiException(
  HttpStatus.UNPROCESSABLE_ENTITY,
  'VALIDATION_ERROR',
  'Error.Language.InvalidFormat',
  [{ code: 'Error.Language.InvalidFormat', path: 'id' }]
)

export const LanguageActionForbiddenException = new ApiException(
  HttpStatus.FORBIDDEN,
  'FORBIDDEN',
  'Error.Language.ActionForbidden',
  [{ code: 'Error.Language.ActionForbidden' }]
)
