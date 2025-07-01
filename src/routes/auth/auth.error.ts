import {
  ConflictError,
  NotFoundError,
  ForbiddenError,
  UnauthorizedError,
  BadRequestError,
  InternalServerError,
  UnprocessableEntityError,
} from 'src/shared/error'

export const AuthError = {
  // --- Account & User ---
  EmailAlreadyExists: ConflictError('auth.error.EMAIL_ALREADY_EXISTS'),
  EmailNotFound: NotFoundError('auth.error.EMAIL_NOT_FOUND'),
  UserNotFound: NotFoundError('auth.error.USER_NOT_FOUND'),
  UserNotActive: ForbiddenError('auth.error.USER_NOT_ACTIVE'),
  UserBlocked: ForbiddenError('auth.error.USER_BLOCKED'),
  AccountLocked: ForbiddenError('auth.error.ACCOUNT_LOCKED'),

  // --- Credentials ---
  InvalidCredentials: UnauthorizedError('auth.error.INVALID_CREDENTIALS'),
  InvalidPassword: UnauthorizedError('auth.error.INVALID_CREDENTIALS', 'password'),
  PasswordsNotMatch: BadRequestError('auth.error.PASSWORDS_NOT_MATCH', 'confirmPassword'),
  SamePassword: BadRequestError('auth.error.SAME_PASSWORD', 'newPassword'),

  // --- OTP & Verification ---
  InvalidOTP: BadRequestError('auth.error.INVALID_OTP', 'code'),
  OTPExpired: BadRequestError('auth.error.OTP_EXPIRED', 'code'),
  OTPSendingFailed: InternalServerError('auth.error.OTP_SENDING_FAILED'),
  VerificationCodeInvalid: BadRequestError('auth.error.VERIFICATION_CODE_INVALID'),
  VerificationCodeNotFound: NotFoundError('auth.error.VERIFICATION_CODE_NOT_FOUND'),

  // --- Two-Factor Authentication ---
  InvalidTOTP: BadRequestError('auth.error.INVALID_TOTP', 'totpCode'),
  TOTPRequired: BadRequestError('auth.error.TOTP_REQUIRED'),
  TOTPAlreadyEnabled: ConflictError('auth.error.TOTP_ALREADY_ENABLED'),
  TOTPNotEnabled: BadRequestError('auth.error.TOTP_NOT_ENABLED'),

  // --- Tokens & Sessions ---
  AccessTokenRequired: UnauthorizedError('auth.error.ACCESS_TOKEN_REQUIRED'),
  InvalidAccessToken: UnauthorizedError('auth.error.INVALID_ACCESS_TOKEN'),
  RefreshTokenRequired: UnauthorizedError('auth.error.REFRESH_TOKEN_REQUIRED'),
  InvalidRefreshToken: UnauthorizedError('auth.error.INVALID_REFRESH_TOKEN'),
  RefreshTokenReused: ForbiddenError('auth.error.REFRESH_TOKEN_REUSED'),
  TokenBlacklisted: UnauthorizedError('auth.error.TOKEN_BLACKLISTED'),
  SessionNotFound: NotFoundError('auth.error.SESSION_NOT_FOUND'),

  // --- CSRF ---
  InvalidCsrfToken: ForbiddenError('auth.error.INVALID_CSRF_TOKEN'),
  CsrfTokenMissing: ForbiddenError('auth.error.CSRF_TOKEN_MISSING'),

  // --- General ---
  InsufficientPermissions: ForbiddenError('auth.error.INSUFFICIENT_PERMISSIONS'),
  RoleNotFound: InternalServerError('auth.error.ROLE_NOT_FOUND'),

  // === Password & Credentials Errors ===
  WeakPassword: BadRequestError('auth.error.WEAK_PASSWORD', 'password'),

  // === OTP Errors ===
  OTPMaxAttempts: BadRequestError('auth.error.OTP_MAX_ATTEMPTS'),
  OTPRequired: BadRequestError('auth.error.OTP_REQUIRED'),

  // === 2FA/TOTP Errors ===
  InvalidTOTPAndCode: BadRequestError('auth.error.INVALID_TOTP_AND_CODE'),
  Disable2FARequiresCode: BadRequestError('auth.error.DISABLE_2FA_REQUIRES_CODE'),
  InvalidRecoveryCode: BadRequestError('auth.error.INVALID_RECOVERY_CODE'),
  StateTokenMissing: BadRequestError('auth.error.STATE_TOKEN_MISSING'),

  // === Token & Session Errors ===
  AccessTokenExpired: UnauthorizedError('auth.error.ACCESS_TOKEN_EXPIRED'),
  SessionExpired: UnauthorizedError('auth.error.SESSION_EXPIRED'),
  SessionRevoked: UnauthorizedError('auth.error.SESSION_REVOKED'),
  SessionUserMismatch: UnauthorizedError('auth.error.SESSION_USER_MISMATCH'),
  InvalidSession: UnauthorizedError('auth.error.INVALID_SESSION'),

  // === Device Errors ===
  DeviceNotFound: NotFoundError('auth.error.DEVICE_NOT_FOUND'),
  DeviceNotTrusted: ForbiddenError('auth.error.DEVICE_NOT_TRUSTED'),
  DeviceInactive: ForbiddenError('auth.error.DEVICE_INACTIVE'),
  SuspiciousDevice: ForbiddenError('auth.error.SUSPICIOUS_DEVICE'),

  // === OAuth & Social Auth Errors ===
  GoogleAuthError: InternalServerError('auth.error.GOOGLE_AUTH_ERROR'),
  GoogleUserInfoError: InternalServerError('auth.error.GOOGLE_USER_INFO_ERROR'),
  GoogleCallbackError: BadRequestError('auth.error.GOOGLE_CALLBACK_ERROR'),
  GoogleAccountLinked: ConflictError('auth.error.GOOGLE_ACCOUNT_LINKED'),
  GoogleNotLinked: BadRequestError('auth.error.GOOGLE_NOT_LINKED'),
  InvalidOAuthState: BadRequestError('auth.error.INVALID_OAUTH_STATE'),
  OAuthCancelled: BadRequestError('auth.error.OAUTH_CANCELLED'),

  // === Verification Errors ===
  VerificationRequired: BadRequestError('auth.error.VERIFICATION_REQUIRED'),
  EmailNotVerified: BadRequestError('auth.error.EMAIL_NOT_VERIFIED'),

  // === System & General Errors ===
  RateLimitExceeded: BadRequestError('auth.error.RATE_LIMIT_EXCEEDED'),
  ServiceUnavailable: InternalServerError('auth.error.SERVICE_UNAVAILABLE'),
  MaintenanceMode: InternalServerError('auth.error.MAINTENANCE_MODE'),
} as const

export type AuthErrorKey = keyof typeof AuthError
