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

export enum TypeOfVerificationCode {
  REGISTER = 'REGISTER',
  RESET_PASSWORD = 'RESET_PASSWORD',
  LOGIN = 'LOGIN',
  LOGIN_2FA = 'LOGIN_2FA',
  DISABLE_2FA = 'DISABLE_2FA',
  SETUP_2FA = 'SETUP_2FA',
  LOGIN_UNTRUSTED_DEVICE_OTP = 'LOGIN_UNTRUSTED_DEVICE_OTP'
}

export type TypeOfVerificationCodeType = (typeof TypeOfVerificationCode)[keyof typeof TypeOfVerificationCode]

export const TwoFactorMethodType = {
  TOTP: 'TOTP',
  OTP: 'OTP',
  RECOVERY: 'RECOVERY'
} as const

export type TwoFactorMethodTypeType = (typeof TwoFactorMethodType)[keyof typeof TwoFactorMethodType]

export const TokenType = {
  OTP: 'OTP',
  SETUP_2FA_TOKEN: 'SETUP_2FA_TOKEN'
} as const

export type TokenTypeType = (typeof TokenType)[keyof typeof TokenType]

export const CookieNames = {
  ACCESS_TOKEN: 'access_token',
  REFRESH_TOKEN: 'refresh_token',
  CSRF_TOKEN: 'xsrf-token'
} as const

export type CookieNamesType = (typeof CookieNames)[keyof typeof CookieNames]

export const SecurityHeaders = {
  CSRF_TOKEN_HEADER: 'x-csrf-token',
  CONTENT_SECURITY_POLICY: 'Content-Security-Policy',
  X_CONTENT_TYPE_OPTIONS: 'X-Content-Type-Options',
  STRICT_TRANSPORT_SECURITY: 'Strict-Transport-Security',
  X_FRAME_OPTIONS: 'X-Frame-Options',
  X_XSS_PROTECTION: 'X-XSS-Protection',
  CACHE_CONTROL: 'Cache-Control'
} as const
