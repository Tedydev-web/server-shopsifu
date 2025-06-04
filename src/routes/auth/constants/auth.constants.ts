import { AuthType, ConditionGuard, CookieNames } from 'src/shared/constants/auth.constant'
import { RedisPrefix } from 'src/shared/utils/redis-keys.utils'

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

// Thời gian các token
export const OTP_EXPIRATION_TIME = 10 * 60 * 1000 // 10 phút
export const MAX_OTP_ATTEMPTS = 5
export const OTP_LENGTH = 6 // Độ dài mã OTP

// Redis keys và prefixes
export const SESSION_KEY_PREFIX = 'session:'
export const SESSION_INVALIDATED_KEY_PREFIX = 'session:invalidated:'
export const SESSION_ARCHIVED_KEY_PREFIX = 'session:archived:'
export const DEVICE_REVERIFY_KEY_PREFIX = 'device:reverify:'
export const REVOKE_HISTORY_KEY_PREFIX = 'session:revoke:history:'

/**
 * TTL cho các keys Redis
 */
export const DEVICE_REVOKE_HISTORY_TTL = 30 * 24 * 60 * 60 // 30 ngày
export const DEVICE_REVERIFICATION_TTL = 7 * 24 * 60 * 60 // 7 ngày
export const LOGIN_HISTORY_TTL = 90 * 24 * 60 * 60 // 90 ngày
export const SESSION_MAXAGE_TTL = 30 * 24 * 60 * 60 // 30 ngày
export const ACCESS_TOKEN_BLACKLIST_TTL = 24 * 60 * 60 // 24 giờ
export const OTP_TTL = 5 * 60 // 5 phút
export const OTP_COOLDOWN_TTL = 60 // 1 phút
export const SLT_TOKEN_TTL = 5 * 60 // 5 phút
export const SLT_CONTEXT_TTL = 10 * 60 // 10 phút
