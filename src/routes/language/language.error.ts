import { GlobalError } from 'src/shared/global.error'

/**
 * Centralized Language Error Definitions
 */
export const LanguageError = {
  // === Language Errors ===
  NotFound: GlobalError.NotFound('language.error.NOT_FOUND'),
  AlreadyExists: GlobalError.Conflict('language.error.ALREADY_EXISTS'),
  CannotDelete: GlobalError.Forbidden('language.error.CANNOT_DELETE'),
} as const

// Type for language error keys for better type safety
export type LanguageErrorKey = keyof typeof LanguageError

// Backward compatibility
export const LanguageAlreadyExistsException = LanguageError.AlreadyExists
