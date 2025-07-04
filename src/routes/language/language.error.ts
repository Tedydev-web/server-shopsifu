import { ExceptionFactory } from 'src/shared/error'

// --- Language-specific Exceptions sử dụng ExceptionFactory ---
export const LanguageAlreadyExistsException = ExceptionFactory.conflict('language.error.ALREADY_EXISTS', 'id')
