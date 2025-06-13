export type RedisKey = string

/**
 * Defines the standardized prefixes for all Redis keys used in the application.
 * Using an enum ensures consistency and avoids magic strings.
 */
export enum RedisPrefix {
  AUTH = 'auth',

  SESSION = 'auth:session',
  SESSIONS_BY_USER = 'auth:user:sessions',
  SESSIONS_BY_DEVICE = 'auth:device:sessions',
  SESSION_INVALIDATED = 'auth:session:invalidated',

  DEVICE_REVERIFY = 'auth:device:reverify',

  TOKEN_ACCESS_BLACKLIST = 'auth:token:access:blacklist',
  TOKEN_REFRESH_BLACKLIST = 'auth:token:refresh:blacklist',
  TOKEN_REFRESH_USED = 'auth:token:refresh:used',

  OTP_DATA = 'auth:otp:data',

  SLT_CONTEXT = 'auth:slt:context',
  SLT_BLACKLIST = 'auth:slt:blacklist',
  SLT_ACTIVE = 'auth:slt:active',

  USER_LOGIN_HISTORY = 'auth:user:login_history',
  USER_LOGIN_FAILURES = 'auth:user:login_failures',
  USER_ACCOUNT_LOCK = 'auth:user:account_lock',
  USER_ACTIVITY = 'auth:user:activity',
  USER_SUSPICIOUS_NOTIFICATION = 'auth:user:suspicious_notification',
  USER_REVERIFY_NEXT_LOGIN = 'auth:user:reverify_next_login',

  CACHE = 'cache',
  CACHE_ROLE = 'cache:role',
  CACHE_PERMISSION = 'cache:permission',
  CACHE_USER_PERMISSIONS = 'cache:user:permissions'
}

/**
 * A static class that provides methods to generate standardized Redis keys.
 * This ensures that all parts of the application access Redis keys in a consistent manner.
 */
export class RedisKeyManager {
  private static a(...parts: (string | number)[]): string {
    return parts.join(':')
  }

  /**
   * Key for a single session hash.
   * @type HASH
   * @example "auth:session:uuid-of-session"
   */
  public static getSessionKey(sessionId: string): string {
    return `${RedisPrefix.AUTH}:session:${sessionId}`
  }

  /**
   * Key for the set of a user's session IDs.
   * @type SET
   * @example "auth:user:sessions:123"
   */
  public static getUserSessionsKey(userId: number): string {
    return `${RedisPrefix.AUTH}:user:${userId}:sessions`
  }

  /**
   * Key for the set of a device's session IDs.
   * @type SET
   * @example "auth:device:sessions:456"
   */
  public static getDeviceSessionsKey(deviceId: number): string {
    return `${RedisPrefix.AUTH}:device:${deviceId}:sessions`
  }

  /**
   * Key for the set of invalidated session IDs.
   * @type SET
   * @example "auth:session:invalidated"
   */
  public static getInvalidatedSessionsKey(): string {
    return RedisPrefix.SESSION_INVALIDATED
  }

  /**
   * Key for the device reverification flag.
   * @type STRING
   * @example "auth:device:reverify:123:456"
   */
  public static getDeviceReverifyKey(userId: number, deviceId: number): string {
    return this.a(RedisPrefix.DEVICE_REVERIFY, userId, deviceId)
  }

  /**
   * Key to flag that a device requires reverification after a sensitive action.
   * @param deviceId - The ID of the device.
   * @returns `auth:device:<deviceId>:reverify`
   */
  public static getDeviceReverificationKey(deviceId: number): string {
    return `${RedisPrefix.AUTH}:device:${deviceId}:reverify`
  }

  /**
   * Key for the device suspicious flag.
   * @type STRING
   * @example "auth:device:suspicious:456"
   */
  public static getDeviceSuspiciousKey(deviceId: number): string {
    return `${RedisPrefix.AUTH}:device:${deviceId}:suspicious`
  }

  /**
   * Key for a blacklisted access token JTI.
   * @type STRING
   * @example "auth:token:access:blacklist:jti-abc"
   */
  public static getAccessTokenBlacklistKey(jti: string): string {
    return `${RedisPrefix.AUTH}:token:access-blacklist:${jti}`
  }

  /**
   * Key for a blacklisted refresh token JTI.
   * @type STRING
   * @example "auth:token:refresh:blacklist:jti-def"
   */
  public static getRefreshTokenBlacklistKey(jti: string): string {
    return `${RedisPrefix.AUTH}:token:refresh-blacklist:${jti}`
  }

  /**
   * Key for a used refresh token JTI.
   * @type STRING
   * @example "auth:token:refresh:used:jti-ghi"
   */
  public static getRefreshTokenUsedKey(jti: string): string {
    return `${RedisPrefix.AUTH}:token:refresh-used:${jti}`
  }

  /**
   * Key for OTP data hash.
   * @type HASH
   * @example "auth:otp:data:REGISTER:user@example.com"
   */
  public static getOtpDataKey(type: string, identifier: string): string {
    return this.a(RedisPrefix.OTP_DATA, type, identifier)
  }

  /**
   * Key for SLT context hash.
   * @type HASH
   * @example "auth:slt:context:jti-jkl"
   */
  public static getSltContextKey(jti: string): string {
    return `${RedisPrefix.AUTH}:slt-context:${jti}`
  }

  /**
   * Key for a blacklisted SLT JTI.
   * @type STRING
   * @example "auth:slt:blacklist:jti-mno"
   */
  public static getSltBlacklistKey(jti: string): string {
    return this.a(RedisPrefix.SLT_BLACKLIST, jti)
  }
  /**
   * Key for tracking active SLT token by user and purpose.
   * @type STRING
   * @example "auth:slt:active:123:VERIFY_2FA"
   */
  public static getSltActiveTokenKey(userId: number, purpose: string): string {
    return this.a(RedisPrefix.SLT_ACTIVE, userId, purpose)
  }

  /**
   * Key for the user login failures counter.
   * @type STRING (Counter)
   * @example "auth:user:login_failures:123"
   */
  public static getLoginFailuresKey(userId: number): string {
    return `${RedisPrefix.AUTH}:user:${userId}:login-failures`
  }

  /**
   * Key for the user account lock flag.
   * @type STRING
   * @example "auth:user:account_lock:123"
   */
  public static getAccountLockKey(userId: number): string {
    return `${RedisPrefix.AUTH}:user:${userId}:account-lock`
  }

  /**
   * Key for the user re-verification flag.
   * @type STRING
   * @example "auth:user:reverify_next_login:123"
   */
  public static getUserReverifyNextLoginKey(userId: number): string {
    return `${RedisPrefix.AUTH}:user:${userId}:reverify-next-login`
  }

  /**
   * Key for the suspicious activity notification cooldown.
   * @type STRING
   * @example "auth:user:suspicious_notification:123:failed_logins"
   */
  public static getSuspiciousActivityNotificationKey(userId: number, ruleType: string): string {
    return `${RedisPrefix.AUTH}:user:${userId}:suspicious-notification:${ruleType}`
  }

  /**
   * Key for the user activity log.
   * @type LIST or STREAM
   * @example "auth:user:activity:123"
   */
  public static getUserActivityKey(userId: number): string {
    return `${RedisPrefix.AUTH}:user:${userId}:activity`
  }

  static getPasswordChangesKey(userId: number): string {
    return `${RedisPrefix.AUTH}:user:${userId}:password-changes`
  }

  /**
   * Key for tracking recent email changes for a user (list).
   * @param userId - The ID of the user.
   * @returns `auth:user:<userId>:email-changes`
   */
  static getEmailChangesKey(userId: number): string {
    return `${RedisPrefix.AUTH}:user:${userId}:email-changes`
  }

  /**
   * Key for tracking recent 2FA status changes for a user (list).
   * @param userId - The ID of the user.
   * @returns `auth:user:<userId>:2fa-changes`
   */
  static getTwoFactorChangesKey(userId: number): string {
    return `${RedisPrefix.AUTH}:user:${userId}:2fa-changes`
  }

  /**
   * Key for storing the last login timestamp for a user.
   * @param userId - The ID of the user.
   */
  static getLastLoginTimestampKey(userId: number): string {
    return `${RedisPrefix.AUTH}:user:${userId}:last-login-timestamp`
  }

  // --- Cache Keys ---

  /**
   * Key for caching a single role by its ID.
   * @type STRING (JSON)
   * @example "cache:role:1"
   */
  public static getRoleCacheKey(roleId: number): string {
    return this.a(RedisPrefix.CACHE_ROLE, roleId)
  }

  /**
   * Key for caching a single role by its name.
   * @type STRING (JSON)
   * @example "cache:role:name:Admin"
   */
  public static getRoleByNameCacheKey(roleName: string): string {
    return this.a(RedisPrefix.CACHE_ROLE, 'name', roleName)
  }

  /**
   * Key for caching the list of all roles.
   * @type STRING (JSON)
   * @example "cache:role:all"
   */
  public static getAllRolesCacheKey(): string {
    return this.a(RedisPrefix.CACHE_ROLE, 'all')
  }

  /**
   * Key for caching a single permission by its ID.
   * @type STRING (JSON)
   * @example "cache:permission:1"
   */
  public static getPermissionCacheKey(permissionId: number): string {
    return this.a(RedisPrefix.CACHE_PERMISSION, permissionId)
  }

  /**
   * Key for caching a single permission by its action and subject.
   * @type STRING (JSON)
   * @example "cache:permission:action:create:subject:user"
   */
  public static getPermissionByActionAndSubjectCacheKey(action: string, subject: string): string {
    return this.a(RedisPrefix.CACHE_PERMISSION, 'action', action, 'subject', subject)
  }

  /**
   * Key for caching the list of all permissions.
   * @type STRING (JSON)
   * @example "cache:permission:all"
   */
  public static getAllPermissionsCacheKey(): string {
    return this.a(RedisPrefix.CACHE_PERMISSION, 'all')
  }
  /**
   * Key for caching a user's permissions.
   * @type STRING (JSON)
   * @example "cache:user:permissions:123"
   */
  public static getUserPermissionsCacheKey(userId: number): string {
    return this.a(RedisPrefix.CACHE_USER_PERMISSIONS, userId)
  }
}
