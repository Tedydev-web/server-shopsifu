import { ExceptionFactory } from 'src/shared/error'

// --- Brand Translation-specific Exceptions sử dụng ExceptionFactory ---
export const BrandTranslationAlreadyExistsException = ExceptionFactory.alreadyExists(
  'brand-translation.error.ALREADY_EXISTS',
  'languageId',
)
