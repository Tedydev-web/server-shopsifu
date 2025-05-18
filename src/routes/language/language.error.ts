import { HttpStatus } from '@nestjs/common'
import { ApiException } from 'src/shared/exceptions/api.exception'

export const LanguageAlreadyExistsException = new ApiException(
  HttpStatus.CONFLICT,
  'RESOURCE_CONFLICT',
  'Error.Language.AlreadyExists', // Key i18n chính
  [{ code: 'Error.Language.AlreadyExists', path: 'id' }] // Detail cụ thể
)
