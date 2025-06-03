import { AuthType, ConditionGuard, CookieNames } from 'src/shared/constants/auth.constant'

export { AuthType, ConditionGuard, CookieNames }

export enum TypeOfVerificationCode {
  REGISTER = 'REGISTER',
  RESET_PASSWORD = 'RESET_PASSWORD',
  LOGIN = 'LOGIN',
  LOGIN_2FA = 'LOGIN_2FA',
  DISABLE_2FA = 'DISABLE_2FA',
  SETUP_2FA = 'SETUP_2FA',
  LOGIN_UNTRUSTED_DEVICE_OTP = 'LOGIN_UNTRUSTED_DEVICE_OTP',
  REVERIFY_SESSION_OTP = 'REVERIFY_SESSION_OTP',
  VERIFY_NEW_EMAIL = 'VERIFY_NEW_EMAIL',
  UNLINK_GOOGLE_ACCOUNT = 'UNLINK_GOOGLE_ACCOUNT',
  REVOKE_SESSIONS = 'REVOKE_SESSIONS',
  REVOKE_ALL_SESSIONS = 'REVOKE_ALL_SESSIONS'
}

export type TypeOfVerificationCodeType = (typeof TypeOfVerificationCode)[keyof typeof TypeOfVerificationCode]

/**
 * Enum phải giữ đồng bộ với schema.prisma
 * enum TwoFactorMethodType {
 *   TOTP
 *   OTP
 *   RECOVERY
 * }
 */
export enum TwoFactorMethodType {
  TOTP = 'TOTP',
  OTP = 'OTP',
  RECOVERY = 'RECOVERY'
}

export type TwoFactorMethodTypeType = (typeof TwoFactorMethodType)[keyof typeof TwoFactorMethodType]

export enum TokenType {
  ACCESS = 'ACCESS',
  REFRESH = 'REFRESH',
  SLT = 'SLT'
}

export type TokenTypeType = (typeof TokenType)[keyof typeof TokenType]

export const OTP_EXPIRATION_TIME = 10 * 60 * 1000 // 10 phút
export const MAX_OTP_ATTEMPTS = 5
export const OTP_LENGTH = 6 // Độ dài mã OTP
