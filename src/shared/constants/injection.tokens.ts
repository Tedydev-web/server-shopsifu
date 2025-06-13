/**
 * Định nghĩa các token injection chung cho toàn ứng dụng
 */

// Redis
export const REDIS_SERVICE = 'REDIS_SERVICE'

// Core Auth Services
export const TOKEN_SERVICE = 'TOKEN_SERVICE'
export const COOKIE_SERVICE = 'COOKIE_SERVICE'
export const HASHING_SERVICE = 'HASHING_SERVICE'
export const EMAIL_SERVICE = 'EMAIL_SERVICE'
export const GEOLOCATION_SERVICE = 'GEOLOCATION_SERVICE'
export const SLT_SERVICE = 'SLT_SERVICE'
export const CRYPTO_SERVICE = 'CRYPTO_SERVICE'

// Module-specific services (that are shared)
export const OTP_SERVICE = 'OTP_SERVICE'
export const DEVICE_SERVICE = 'DEVICE_SERVICE'
export const USER_ACTIVITY_SERVICE = 'USER_ACTIVITY_SERVICE'
export const USER_AGENT_SERVICE = 'USER_AGENT_SERVICE'

// Global services
export const LOGGER_SERVICE = 'LOGGER_SERVICE'

export const TWO_FACTOR_SERVICE = 'TWO_FACTOR_SERVICE'
export const CORE_SERVICE = 'CORE_SERVICE'
export const SESSIONS_SERVICE = 'SESSIONS_SERVICE'
export const SOCIAL_SERVICE = 'SOCIAL_SERVICE'
