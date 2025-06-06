/**
 * Auth Constants
 */
import { RedisPrefix } from 'src/shared/utils/redis-keys.utils'

export enum AuthType {
  JWT = 'JWT',
  ApiKey = 'ApiKey',
  Basic = 'Basic',
  Bearer = 'Bearer',
  None = 'None'
}

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

/**
 * Security Headers
 */
export enum SecurityHeaders {
  XSRF_TOKEN_HEADER = 'xsrf-token',
  CSRF_TOKEN_HEADER = 'x-csrf-token',
  XSS_PROTECTION = 'X-XSS-Protection',
  CONTENT_TYPE_OPTIONS = 'X-Content-Type-Options',
  FRAME_OPTIONS = 'X-Frame-Options',
  HSTS = 'Strict-Transport-Security',
  CONTENT_SECURITY_POLICY = 'Content-Security-Policy',
  CACHE_CONTROL = 'Cache-Control',
  REFERRER_POLICY = 'Referrer-Policy',
  PERMITTED_CROSS_DOMAIN_POLICIES = 'X-Permitted-Cross-Domain-Policies',
  EXPECT_CT = 'Expect-CT'
}

export const REQUEST_USER_KEY = 'user'

/**
 * Verification types for OTP and short-lived tokens
 */
export enum TypeOfVerificationCode {
  REGISTER = 'REGISTER',
  RESET_PASSWORD = 'RESET_PASSWORD',
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

/**
 * Two-factor authentication methods
 * Enum này phải giữ đồng bộ với schema.prisma:
 * enum TwoFactorMethodType {
 *   TOTP
 *   OTP
 *   RECOVERY
 * }
 */
export enum TwoFactorMethodType {
  TOTP = 'TOTP',
  RECOVERY = 'RECOVERY'
}

export type TwoFactorMethodTypeType = (typeof TwoFactorMethodType)[keyof typeof TwoFactorMethodType]

/**
 * Token types
 */
export enum TokenType {
  ACCESS = 'ACCESS',
  REFRESH = 'REFRESH',
  SLT = 'SLT'
}

export type TokenTypeType = (typeof TokenType)[keyof typeof TokenType]

/**
 * Thời gian các token
 */
export const OTP_EXPIRATION_TIME = 10 * 60 * 1000 // 10 phút
export const MAX_OTP_ATTEMPTS = 5
export const OTP_LENGTH = 6 // Độ dài mã OTP
export const OTP_COOLDOWN_SECONDS = 60 // 1 minute
export const SLT_EXPIRY_SECONDS = 300 // 5 minutes
export const SLT_MAX_ATTEMPTS = 5

/**
 * Redis keys và prefixes
 */
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
