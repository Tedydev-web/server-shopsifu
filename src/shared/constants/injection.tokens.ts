/**
 * Định nghĩa các token injection chung cho toàn ứng dụng
 */

// Redis
export const REDIS_CLIENT = 'REDIS_CLIENT'
export const REDIS_SERVICE = 'REDIS_SERVICE'

// Core Auth Services
export const TOKEN_SERVICE = 'TOKEN_SERVICE'
export const COOKIE_SERVICE = 'COOKIE_SERVICE'
export const HASHING_SERVICE = 'HASHING_SERVICE'
export const EMAIL_SERVICE = 'EMAIL_SERVICE'
export const GEOLOCATION_SERVICE = 'GEOLOCATION_SERVICE'
export const SLT_SERVICE = 'SLT_SERVICE'

// Module-specific services (that are shared)
export const OTP_SERVICE = 'OTP_SERVICE'
export const SESSION_SERVICE = 'SESSION_SERVICE'
export const DEVICE_SERVICE = 'DEVICE_SERVICE'

// Global services
export const LOGGER_SERVICE = 'LOGGER_SERVICE'
