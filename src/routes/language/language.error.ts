import { GlobalError } from 'src/shared/global.error'

/**
 * Centralized Language Error Definitions
 */
export const LanguageError = {
  // === Language Errors ===
  NotFound: GlobalError.NotFound('language.error.NOT_FOUND'),
  AlreadyExists: GlobalError.Conflict('language.error.ALREADY_EXISTS'),
  InvalidId: GlobalError.BadRequest('language.error.INVALID_ID'),
  CannotDelete: GlobalError.Forbidden('language.error.CANNOT_DELETE'),
  OperationFailed: GlobalError.InternalServerError('language.error.OPERATION_FAILED'),
} as const

// Type for language error keys for better type safety
export type LanguageErrorKey = keyof typeof LanguageError

// Backward compatibility
export const LanguageAlreadyExistsException = LanguageError.AlreadyExists
