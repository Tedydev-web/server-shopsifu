import { AuthError } from './auth.error'

export const CsrfError = {
  InvalidToken: AuthError.InvalidCsrfToken,
  TokenMissing: AuthError.CsrfTokenMissing,
} as const

export type CsrfErrorKey = keyof typeof CsrfError
