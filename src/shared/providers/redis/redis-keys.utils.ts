export type RedisKey = string

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

export class RedisKeyManager {
  private static a(...parts: (string | number)[]): string {
    return parts.join(':')
  }

  public static getSessionKey(sessionId: string): string {
    return `${RedisPrefix.AUTH}:session:${sessionId}`
  }

  public static getUserSessionsKey(userId: number): string {
    return `${RedisPrefix.AUTH}:user:${userId}:sessions`
  }

  public static getDeviceSessionsKey(deviceId: number): string {
    return `${RedisPrefix.AUTH}:device:${deviceId}:sessions`
  }

  public static getInvalidatedSessionsKey(): string {
    return RedisPrefix.SESSION_INVALIDATED
  }

  public static getDeviceReverifyKey(userId: number, deviceId: number): string {
    return this.a(RedisPrefix.DEVICE_REVERIFY, userId, deviceId)
  }

  public static getDeviceReverificationKey(deviceId: number): string {
    return `${RedisPrefix.AUTH}:device:${deviceId}:reverify`
  }

  public static getDeviceSuspiciousKey(deviceId: number): string {
    return `${RedisPrefix.AUTH}:device:${deviceId}:suspicious`
  }

  public static getAccessTokenBlacklistKey(jti: string): string {
    return `${RedisPrefix.AUTH}:token:access-blacklist:${jti}`
  }

  public static getRefreshTokenBlacklistKey(jti: string): string {
    return `${RedisPrefix.AUTH}:token:refresh-blacklist:${jti}`
  }

  public static getRefreshTokenUsedKey(jti: string): string {
    return `${RedisPrefix.AUTH}:token:refresh-used:${jti}`
  }

  public static getOtpDataKey(type: string, identifier: string): string {
    return this.a(RedisPrefix.OTP_DATA, type, identifier)
  }

  public static getSltContextKey(jti: string): string {
    return `${RedisPrefix.AUTH}:slt-context:${jti}`
  }

  public static getSltBlacklistKey(jti: string): string {
    return this.a(RedisPrefix.SLT_BLACKLIST, jti)
  }

  public static getSltActiveTokenKey(userId: number, purpose: string): string {
    return this.a(RedisPrefix.SLT_ACTIVE, userId, purpose)
  }

  public static getLoginFailuresKey(userId: number): string {
    return `${RedisPrefix.AUTH}:user:${userId}:login-failures`
  }

  public static getAccountLockKey(userId: number): string {
    return `${RedisPrefix.AUTH}:user:${userId}:account-lock`
  }

  public static getUserReverifyNextLoginKey(userId: number): string {
    return `${RedisPrefix.AUTH}:user:${userId}:reverify-next-login`
  }

  public static getSuspiciousActivityNotificationKey(userId: number, ruleType: string): string {
    return `${RedisPrefix.AUTH}:user:${userId}:suspicious-notification:${ruleType}`
  }

  public static getUserActivityKey(userId: number): string {
    return `${RedisPrefix.AUTH}:user:${userId}:activity`
  }

  static getPasswordChangesKey(userId: number): string {
    return `${RedisPrefix.AUTH}:user:${userId}:password-changes`
  }

  static getEmailChangesKey(userId: number): string {
    return `${RedisPrefix.AUTH}:user:${userId}:email-changes`
  }

  static getTwoFactorChangesKey(userId: number): string {
    return `${RedisPrefix.AUTH}:user:${userId}:2fa-changes`
  }

  static getLastLoginTimestampKey(userId: number): string {
    return `${RedisPrefix.AUTH}:user:${userId}:last-login-timestamp`
  }

  public static getRoleCacheKey(roleId: number): string {
    return this.a(RedisPrefix.CACHE_ROLE, roleId)
  }

  public static getRoleByNameCacheKey(roleName: string): string {
    return this.a(RedisPrefix.CACHE_ROLE, 'name', roleName)
  }

  public static getAllRolesCacheKey(): string {
    return this.a(RedisPrefix.CACHE_ROLE, 'all')
  }

  public static getPermissionCacheKey(permissionId: number): string {
    return this.a(RedisPrefix.CACHE_PERMISSION, permissionId)
  }

  public static getPermissionByActionAndSubjectCacheKey(action: string, subject: string): string {
    return this.a(RedisPrefix.CACHE_PERMISSION, 'action', action, 'subject', subject)
  }

  public static getAllPermissionsCacheKey(): string {
    return this.a(RedisPrefix.CACHE_PERMISSION, 'all')
  }

  public static getUserPermissionsCacheKey(userId: number): string {
    return this.a(RedisPrefix.CACHE_USER_PERMISSIONS, userId)
  }
}
