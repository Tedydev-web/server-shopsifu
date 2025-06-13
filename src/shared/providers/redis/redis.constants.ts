export const IORedisKey = Symbol('IOREDIS_CLIENT')

export const SESSION_KEY_PREFIX = 'session:'
export const SESSION_INVALIDATED_KEY_PREFIX = 'session:invalidated:'
export const SESSION_ARCHIVED_KEY_PREFIX = 'session:archived:'
export const DEVICE_REVERIFY_KEY_PREFIX = 'device:reverify:'
export const REVOKE_HISTORY_KEY_PREFIX = 'session:revoke:history:'

export const DEVICE_REVOKE_HISTORY_TTL = 30 * 24 * 60 * 60 // 30 days
export const DEVICE_REVERIFICATION_TTL = 7 * 24 * 60 * 60 // 7 days
export const LOGIN_HISTORY_TTL = 90 * 24 * 60 * 60 // 90 days
export const SESSION_MAXAGE_TTL = 30 * 24 * 60 * 60 // 30 days (used for session cookie maxAge and Redis key TTL)
export const ACCESS_TOKEN_BLACKLIST_TTL = 24 * 60 * 60 // 24 hours (for blacklisted JWT IDs after logout)

export const ROLE_CACHE_TTL = 60 * 60 // 1 hour
export const ALL_ROLES_CACHE_TTL = 60 * 60 // 1 hour
export const PERMISSION_CACHE_TTL = 60 * 60 // 1 hour
export const ALL_PERMISSIONS_CACHE_TTL = 60 * 60 // 1 hour
