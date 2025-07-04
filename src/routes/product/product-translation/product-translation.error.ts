import { ExceptionFactory } from 'src/shared/error'

// --- Product Translation-specific Exceptions sử dụng ExceptionFactory ---
export const ProductTranslationAlreadyExistsException = ExceptionFactory.alreadyExists(
  'product-translation.error.ALREADY_EXISTS',
  'productId',
)
