export enum AuthType {
  JWT = 'JWT',
  ApiKey = 'ApiKey',
  Basic = 'Basic',
  Bearer = 'Bearer',
  None = 'None'
}

export enum TwoFactorMethodType {
  EMAIL = 'EMAIL',
  TOTP = 'TOTP',
  RECOVERY_CODE = 'RECOVERY_CODE'
}

export enum DeviceRiskLevel {
  LOW = 'LOW',
  MEDIUM = 'MEDIUM',
  HIGH = 'HIGH'
}

export enum UserActivityType {
  LOGIN_ATTEMPT = 'LOGIN_ATTEMPT',
  LOGIN_SUCCESS = 'LOGIN_SUCCESS',
  LOGIN_FAILURE = 'LOGIN_FAILURE',
  PASSWORD_CHANGED = 'PASSWORD_CHANGED',
  EMAIL_CHANGED = 'EMAIL_CHANGED',
  PROFILE_UPDATED = 'PROFILE_UPDATED',
  TWO_FACTOR_ENABLED = 'TWO_FACTOR_ENABLED',
  TWO_FACTOR_DISABLED = 'TWO_FACTOR_DISABLED',
  RECOVERY_ATTEMPT = 'RECOVERY_ATTEMPT',
  SUSPICIOUS_ACTIVITY = 'SUSPICIOUS_ACTIVITY',
  ACCOUNT_LOCKED = 'ACCOUNT_LOCKED',
  ACCOUNT_UNLOCKED = 'ACCOUNT_UNLOCKED'
}

export enum ActivitySeverity {
  INFO = 'INFO',
  WARNING = 'WARNING',
  CRITICAL = 'CRITICAL'
}

export const OTP_LENGTH = 6 // OTP length
export const SLT_EXPIRY_SECONDS = 300 // SLT expiry time in seconds
export const SLT_MAX_ATTEMPTS = 5 // Maximum attempts for SLT

export type AuthTypeType = (typeof AuthType)[keyof typeof AuthType]

export enum ConditionGuard {
  PassThrough = 'PassThrough',
  IsPublic = 'IsPublic',
  RolesOnly = 'RolesOnly',
  PermissionsOnly = 'PermissionsOnly',
  RolesAndPermissions = 'RolesAndPermissions',
  And = 'And'
}

export type ConditionGuardType = (typeof ConditionGuard)[keyof typeof ConditionGuard]

export enum CookieNames {
  ACCESS_TOKEN = 'access_token',
  REFRESH_TOKEN = 'refresh_token',
  SLT_TOKEN = 'slt_token',
  XSRF_TOKEN = 'xsrf-token',
  OAUTH_NONCE = 'oauth_nonce',
  OAUTH_PENDING_LINK = 'oauth_pending_link',
  NOTIFICATION_CONSENT = 'notification_consent'
}

export type CookieNamesType = (typeof CookieNames)[keyof typeof CookieNames]

export const REQUEST_USER_KEY = 'user'

export enum TypeOfVerificationCode {
  REGISTER = 'REGISTER',
  RESET_PASSWORD = 'RESET_PASSWORD',
  CHANGE_PASSWORD = 'CHANGE_PASSWORD',
  LOGIN = 'LOGIN',
  DISABLE_2FA = 'DISABLE_2FA',
  SETUP_2FA = 'SETUP_2FA',
  REVERIFY_SESSION_OTP = 'REVERIFY_SESSION_OTP',
  VERIFY_NEW_EMAIL = 'VERIFY_NEW_EMAIL',
  UNLINK_GOOGLE_ACCOUNT = 'UNLINK_GOOGLE_ACCOUNT',
  REVOKE_SESSIONS = 'REVOKE_SESSIONS',
  REVOKE_ALL_SESSIONS = 'REVOKE_ALL_SESSIONS',
  REGENERATE_2FA_CODES = 'REGENERATE_2FA_CODES',
  CREATE_USER = 'CREATE_USER'
}

export type TypeOfVerificationCodeType = (typeof TypeOfVerificationCode)[keyof typeof TypeOfVerificationCode]

export type TwoFactorMethodTypeType = (typeof TwoFactorMethodType)[keyof typeof TwoFactorMethodType]

export enum TokenType {
  ACCESS = 'ACCESS',
  REFRESH = 'REFRESH',
  SLT = 'SLT'
}

export type TokenTypeType = (typeof TokenType)[keyof typeof TokenType]
