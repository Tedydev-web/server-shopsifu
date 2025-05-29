export enum TypeOfVerificationCode {
  REGISTER = 'REGISTER',
  RESET_PASSWORD = 'RESET_PASSWORD',
  LOGIN = 'LOGIN',
  LOGIN_2FA = 'LOGIN_2FA',
  DISABLE_2FA = 'DISABLE_2FA',
  SETUP_2FA = 'SETUP_2FA',
  LOGIN_UNTRUSTED_DEVICE_OTP = 'LOGIN_UNTRUSTED_DEVICE_OTP',
  REVERIFY_SESSION_OTP = 'REVERIFY_SESSION_OTP',
  VERIFY_NEW_EMAIL = 'VERIFY_NEW_EMAIL'
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

export const VERIFICATION_JWT_EXPIRES_IN = '5m'
export const SLT_JWT_EXPIRES_IN = '5m'

export const SESSION_ID_LENGTH = 24

export const MAX_SLT_ATTEMPTS = 5
