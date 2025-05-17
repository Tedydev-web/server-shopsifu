export const REQUEST_USER_KEY = 'user'

export const AuthType = {
  Bearer: 'Bearer',
  None: 'None',
  APIKey: 'ApiKey'
} as const

export type AuthTypeType = (typeof AuthType)[keyof typeof AuthType]

export const ConditionGuard = {
  And: 'and',
  Or: 'or'
} as const

export type ConditionGuardType = (typeof ConditionGuard)[keyof typeof ConditionGuard]

export const UserStatus = {
  ACTIVE: 'ACTIVE',
  INACTIVE: 'INACTIVE',
  BLOCKED: 'BLOCKED'
} as const

export const TypeOfVerificationCode = {
  REGISTER: 'REGISTER',
  FORGOT_PASSWORD: 'FORGOT_PASSWORD',
  LOGIN: 'LOGIN',
  DISABLE_2FA: 'DISABLE_2FA',
  SETUP_2FA: 'SETUP_2FA'
} as const

export type TypeOfVerificationCodeType = (typeof TypeOfVerificationCode)[keyof typeof TypeOfVerificationCode]

export const TwoFactorMethodType = {
  TOTP: 'TOTP',
  OTP: 'OTP',
  RECOVERY: 'RECOVERY'
} as const

export type TwoFactorMethodTypeType = (typeof TwoFactorMethodType)[keyof typeof TwoFactorMethodType]

export const TokenType = {
  LOGIN_SESSION: 'LOGIN_SESSION',
  OTP: 'OTP',
  TOTP_SETUP: 'TOTP_SETUP',
  RECOVERY: 'RECOVERY'
} as const

export type TokenTypeType = (typeof TokenType)[keyof typeof TokenType]

// Thêm constants cho cookie-based auth
export const CookieNames = {
  ACCESS_TOKEN: 'access_token',
  REFRESH_TOKEN: 'refresh_token',
  SESSION_ID: 'session_id',
  CSRF_TOKEN: 'xsrf-token'
} as const

export type CookieNamesType = (typeof CookieNames)[keyof typeof CookieNames]

export const SecurityHeaders = {
  CONTENT_SECURITY_POLICY: 'Content-Security-Policy',
  X_CONTENT_TYPE_OPTIONS: 'X-Content-Type-Options',
  STRICT_TRANSPORT_SECURITY: 'Strict-Transport-Security',
  X_FRAME_OPTIONS: 'X-Frame-Options',
  CACHE_CONTROL: 'Cache-Control',
  X_XSS_PROTECTION: 'X-XSS-Protection',
  CSRF_TOKEN_HEADER: 'x-csrf-token'
} as const
