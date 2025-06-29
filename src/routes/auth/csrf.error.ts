import { AuthError } from './auth.error'

/**
 * Centralized CSRF Error Definitions.
 * These errors are aliases from AuthError for semantic clarity.
 */
export const CsrfError = {
  InvalidToken: AuthError.InvalidCsrfToken,
  TokenMissing: AuthError.CsrfTokenMissing,
} as const

export type CsrfErrorKey = keyof typeof CsrfError
