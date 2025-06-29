import { GlobalError } from 'src/shared/global.error'

export const AuthError = {
  // --- Account & User ---
  EmailAlreadyExists: GlobalError.Conflict('auth.error.EMAIL_ALREADY_EXISTS'),
  EmailNotFound: GlobalError.NotFound('auth.error.EMAIL_NOT_FOUND'),
  UserNotFound: GlobalError.NotFound('auth.error.USER_NOT_FOUND'),
  UserNotActive: GlobalError.Forbidden('auth.error.USER_NOT_ACTIVE'),
  UserBlocked: GlobalError.Forbidden('auth.error.USER_BLOCKED'),
  AccountLocked: GlobalError.Forbidden('auth.error.ACCOUNT_LOCKED'),

  // --- Credentials ---
  InvalidCredentials: GlobalError.Unauthorized('auth.error.INVALID_CREDENTIALS'),
  InvalidPassword: GlobalError.Unauthorized('auth.error.INVALID_CREDENTIALS', [
    { path: 'password', message: 'auth.error.INVALID_PASSWORD' },
  ]),
  PasswordsNotMatch: GlobalError.BadRequest('global.error.BAD_REQUEST', [
    { path: 'confirmPassword', message: 'auth.error.PASSWORDS_NOT_MATCH' },
  ]),
  SamePassword: GlobalError.BadRequest('global.error.BAD_REQUEST', [
    { path: 'newPassword', message: 'auth.error.SAME_PASSWORD' },
  ]),

  // --- OTP & Verification ---
  InvalidOTP: GlobalError.BadRequest('global.error.BAD_REQUEST', [{ path: 'code', message: 'auth.error.INVALID_OTP' }]),
  OTPExpired: GlobalError.BadRequest('global.error.BAD_REQUEST', [{ path: 'code', message: 'auth.error.OTP_EXPIRED' }]),
  OTPSendingFailed: GlobalError.InternalServerError('auth.error.OTP_SENDING_FAILED'),
  VerificationCodeInvalid: GlobalError.BadRequest('auth.error.VERIFICATION_CODE_INVALID'),
  VerificationCodeNotFound: GlobalError.NotFound('auth.error.VERIFICATION_CODE_NOT_FOUND'),

  // --- Two-Factor Authentication ---
  InvalidTOTP: GlobalError.BadRequest('global.error.BAD_REQUEST', [
    { path: 'totpCode', message: 'auth.error.INVALID_TOTP' },
  ]),
  TOTPRequired: GlobalError.BadRequest('auth.error.TOTP_REQUIRED'),
  TOTPAlreadyEnabled: GlobalError.Conflict('auth.error.TOTP_ALREADY_ENABLED'),
  TOTPNotEnabled: GlobalError.BadRequest('auth.error.TOTP_NOT_ENABLED'),

  // --- Tokens & Sessions ---
  AccessTokenRequired: GlobalError.Unauthorized('auth.error.ACCESS_TOKEN_REQUIRED'),
  InvalidAccessToken: GlobalError.Unauthorized('auth.error.INVALID_ACCESS_TOKEN'),
  RefreshTokenRequired: GlobalError.Unauthorized('auth.error.REFRESH_TOKEN_REQUIRED'),
  InvalidRefreshToken: GlobalError.Unauthorized('auth.error.INVALID_REFRESH_TOKEN'),
  RefreshTokenReused: GlobalError.Forbidden('auth.error.REFRESH_TOKEN_REUSED'),
  TokenBlacklisted: GlobalError.Unauthorized('auth.error.TOKEN_BLACKLISTED'),
  SessionNotFound: GlobalError.NotFound('auth.error.SESSION_NOT_FOUND'),

  // --- CSRF ---
  InvalidCsrfToken: GlobalError.Forbidden('auth.error.INVALID_CSRF_TOKEN'),
  CsrfTokenMissing: GlobalError.Forbidden('auth.error.CSRF_TOKEN_MISSING'),

  // --- General ---
  InsufficientPermissions: GlobalError.Forbidden('auth.error.INSUFFICIENT_PERMISSIONS'),
  RoleNotFound: GlobalError.InternalServerError('auth.error.ROLE_NOT_FOUND'), // Should be internal, client should not know

  // === Password & Credentials Errors ===
  WeakPassword: GlobalError.BadRequest('auth.error.WEAK_PASSWORD'),

  // === OTP Errors ===
  OTPMaxAttempts: GlobalError.BadRequest('auth.error.OTP_MAX_ATTEMPTS'),
  OTPRequired: GlobalError.BadRequest('auth.error.OTP_REQUIRED'),

  // === 2FA/TOTP Errors ===
  InvalidTOTPAndCode: GlobalError.BadRequest('auth.error.INVALID_TOTP_AND_CODE'),
  Disable2FARequiresCode: GlobalError.BadRequest('auth.error.DISABLE_2FA_REQUIRES_CODE'),
  InvalidRecoveryCode: GlobalError.BadRequest('auth.error.INVALID_RECOVERY_CODE'),
  StateTokenMissing: GlobalError.BadRequest('auth.error.STATE_TOKEN_MISSING'),

  // === Token & Session Errors ===
  AccessTokenExpired: GlobalError.Unauthorized('auth.error.ACCESS_TOKEN_EXPIRED'),
  SessionExpired: GlobalError.Unauthorized('auth.error.SESSION_EXPIRED'),
  SessionRevoked: GlobalError.Unauthorized('auth.error.SESSION_REVOKED'),
  SessionUserMismatch: GlobalError.Unauthorized('auth.error.SESSION_USER_MISMATCH'),
  InvalidSession: GlobalError.Unauthorized('auth.error.INVALID_SESSION'),

  // === Device Errors ===
  DeviceNotFound: GlobalError.NotFound('auth.error.DEVICE_NOT_FOUND'),
  DeviceNotTrusted: GlobalError.Forbidden('auth.error.DEVICE_NOT_TRUSTED'),
  DeviceInactive: GlobalError.Forbidden('auth.error.DEVICE_INACTIVE'),
  SuspiciousDevice: GlobalError.Forbidden('auth.error.SUSPICIOUS_DEVICE'),

  // === OAuth & Social Auth Errors ===
  GoogleAuthError: GlobalError.InternalServerError('auth.error.GOOGLE_AUTH_ERROR'),
  GoogleUserInfoError: GlobalError.InternalServerError('auth.error.GOOGLE_USER_INFO_ERROR'),
  GoogleCallbackError: GlobalError.BadRequest('auth.error.GOOGLE_CALLBACK_ERROR'),
  GoogleAccountLinked: GlobalError.Conflict('auth.error.GOOGLE_ACCOUNT_LINKED'),
  GoogleNotLinked: GlobalError.BadRequest('auth.error.GOOGLE_NOT_LINKED'),
  InvalidOAuthState: GlobalError.BadRequest('auth.error.INVALID_OAUTH_STATE'),
  OAuthCancelled: GlobalError.BadRequest('auth.error.OAUTH_CANCELLED'),

  // === Verification Errors ===
  VerificationRequired: GlobalError.BadRequest('auth.error.VERIFICATION_REQUIRED'),
  EmailNotVerified: GlobalError.BadRequest('auth.error.EMAIL_NOT_VERIFIED'),

  // === System & General Errors ===
  RateLimitExceeded: GlobalError.BadRequest('auth.error.RATE_LIMIT_EXCEEDED'),
  ServiceUnavailable: GlobalError.InternalServerError('auth.error.SERVICE_UNAVAILABLE'),
  MaintenanceMode: GlobalError.InternalServerError('auth.error.MAINTENANCE_MODE'),
} as const

export type AuthErrorKey = keyof typeof AuthError
