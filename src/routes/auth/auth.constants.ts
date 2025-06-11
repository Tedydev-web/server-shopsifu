export enum AuthType {
  JWT = 'JWT',
  ApiKey = 'ApiKey',
  Basic = 'Basic',
  Bearer = 'Bearer',
  None = 'None'
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
  REGENERATE_2FA_CODES = 'REGENERATE_2FA_CODES'
}

export type TypeOfVerificationCodeType = (typeof TypeOfVerificationCode)[keyof typeof TypeOfVerificationCode]

export enum TwoFactorMethodType {
  EMAIL = 'EMAIL',
  AUTHENTICATOR_APP = 'AUTHENTICATOR_APP',
  RECOVERY_CODE = 'RECOVERY_CODE'
}

export type TwoFactorMethodTypeType = (typeof TwoFactorMethodType)[keyof typeof TwoFactorMethodType]

export enum TokenType {
  ACCESS = 'ACCESS',
  REFRESH = 'REFRESH',
  SLT = 'SLT'
}

export type TokenTypeType = (typeof TokenType)[keyof typeof TokenType]
