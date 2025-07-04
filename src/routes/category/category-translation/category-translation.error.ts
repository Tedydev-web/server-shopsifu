import { ExceptionFactory } from 'src/shared/error'

// --- Category Translation-specific Exceptions sử dụng ExceptionFactory ---
export const CategoryTranslationAlreadyExistsException = ExceptionFactory.alreadyExists(
  'category-translation.error.ALREADY_EXISTS',
  'languageId',
)
