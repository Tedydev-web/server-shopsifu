export enum RedisPrefix {
  CACHE = 'cache',
  SESSION = 'session',
  USER = 'user',
  TOKEN = 'token',
  SLT = 'slt',
  DEVICE = 'device',
  ROLE = 'role',
  PERMISSION = 'permission',
  // Thêm các prefix khác khi cần
}

export class RedisKeyManager {
  private static a(...parts: (string | number)[]): string {
    return parts.join(':')
  }

  // --- Generic Cache Keys ---
  public static getCacheKey(prefix: RedisPrefix, ...parts: (string | number)[]): string {
    return this.a(prefix, ...parts)
  }

  // --- Language Cache Example ---
  public static getAllLanguagesCacheKey(): string {
    return this.a(RedisPrefix.CACHE, 'languages', 'all')
  }

  // --- Session Related Keys Example ---
  public static getSessionKey(sessionId: string): string {
    return this.a(RedisPrefix.SESSION, sessionId)
  }

  public static getUserSessionsKey(userId: number): string {
    return this.a(RedisPrefix.USER, userId, 'sessions')
  }

  // --- Token State Management ---
  public static getUsedRefreshTokenKey(jti: string): string {
    return this.a(RedisPrefix.TOKEN, 'used_rt', jti)
  }

  public static getBlacklistedTokenKey(jti: string): string {
    return this.a(RedisPrefix.TOKEN, 'blacklist', jti)
  }

  // --- SLT (State-Linking Token) Keys ---
  public static getSltContextKey(jti: string): string {
    return this.a(RedisPrefix.SLT, 'context', jti)
  }

  // --- Device Cache Keys ---
  public static getDeviceStatusKey(deviceId: number): string {
    return this.a(RedisPrefix.DEVICE, 'status', deviceId)
  }

  // --- Role Cache Keys ---
  public static getRolePermissionsKey(roleId: number): string {
    return this.a(RedisPrefix.ROLE, 'permissions', roleId)
  }

  // --- Resource Path Mapping Cache Keys ---
  public static getResourcePathMappingKey(resource: string): string {
    return this.a(RedisPrefix.CACHE, 'resource_mapping', resource)
  }
}
