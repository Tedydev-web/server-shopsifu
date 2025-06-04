/**
 * Interface mô tả một Redis key prefix
 */
export interface RedisKeyPrefix {
  value: string
  description: string
}

/**
 * Enum chứa tất cả các prefix cho Redis key
 */
export enum RedisPrefix {
  // Các prefix cho phiên
  SESSION = 'session:',
  SESSION_INVALIDATED = 'session:invalidated:',
  SESSION_ARCHIVED = 'session:archived:',
  SESSION_REVOKE_HISTORY = 'session:revoke:history:',
  SESSION_USER = 'sessions:user:',
  SESSION_DEVICE = 'sessions:device:',
  LOGIN_HISTORY = 'login_history:user:',

  // Các prefix cho thiết bị
  DEVICE = 'device:',
  DEVICE_REVERIFY = 'device:reverify:',

  // Các prefix cho token
  ACCESS_TOKEN_BLACKLIST = 'access_token_blacklist:',
  REFRESH_TOKEN_BLACKLIST = 'refresh_token_blacklist:',
  REFRESH_TOKEN_USED = 'refresh_token_used:',

  // Các prefix cho OTP
  OTP = 'otp:',
  OTP_LAST_SENT = 'otp:last_sent:',

  // Các prefix cho SLT (Short-Lived Token)
  SLT_CONTEXT = 'slt:context:',
  SLT_BLACKLIST = 'slt:blacklist:',

  // Các prefix cho user
  INVALIDATED_USER = 'invalidated:user:',
  INVALIDATED_USERS_SET = 'invalidated:users',

  // Các prefix cho cache
  CACHE = 'cache:',

  // Prefix cho user activity
  USER_ACTIVITY = 'user_activity:',
  LOGIN_FAILURES = 'login_failures:user:',
  LAST_LOGIN = 'last_login:user:',
  PASSWORD_CHANGES = 'password_changes:user:',
  ACCOUNT_LOCK = 'account_lock:user:',
  SUSPICIOUS_NOTIFICATION = 'suspicious_notification:user:'
}

/**
 * Lớp tiện ích quản lý Redis key
 */
export class RedisKeyManager {
  /**
   * Tạo key cho session
   * @param sessionId ID của phiên
   */
  public static sessionKey(sessionId: string): string {
    return `${RedisPrefix.SESSION}${sessionId}`
  }

  /**
   * Tạo key cho danh sách session của user
   * @param userId ID của người dùng
   */
  public static userSessionsKey(userId: number): string {
    return `${RedisPrefix.SESSION_USER}${userId}`
  }

  /**
   * Tạo key cho danh sách session của thiết bị
   * @param deviceId ID của thiết bị
   */
  public static deviceSessionsKey(deviceId: number): string {
    return `${RedisPrefix.SESSION_DEVICE}${deviceId}`
  }

  /**
   * Tạo key cho lịch sử đăng nhập của user
   * @param userId ID của người dùng
   */
  public static userLoginHistoryKey(userId: number): string {
    return `${RedisPrefix.LOGIN_HISTORY}${userId}`
  }

  /**
   * Tạo key cho session đã bị vô hiệu hóa
   * @param sessionId ID của phiên
   */
  public static sessionInvalidatedKey(sessionId: string): string {
    return `${RedisPrefix.SESSION_INVALIDATED}${sessionId}`
  }

  /**
   * Tạo key cho session đã được lưu trữ
   * @param sessionId ID của phiên
   */
  public static sessionArchivedKey(sessionId: string): string {
    return `${RedisPrefix.SESSION_ARCHIVED}${sessionId}`
  }

  /**
   * Tạo key cho lịch sử thu hồi session
   * @param sessionId ID của phiên
   */
  public static sessionRevokeHistoryKey(sessionId: string): string {
    return `${RedisPrefix.SESSION_REVOKE_HISTORY}${sessionId}`
  }

  /**
   * Tạo key cho việc yêu cầu xác thực lại thiết bị
   * @param userId ID của người dùng
   * @param deviceId ID của thiết bị
   */
  public static deviceReverifyKey(userId: number, deviceId: number): string {
    return `${RedisPrefix.DEVICE_REVERIFY}${userId}:${deviceId}`
  }

  /**
   * Tạo key cho blacklist của access token
   * @param jti JWT ID của token
   */
  public static accessTokenBlacklistKey(jti: string): string {
    return `${RedisPrefix.ACCESS_TOKEN_BLACKLIST}${jti}`
  }

  /**
   * Tạo key cho blacklist của refresh token
   * @param jti JWT ID của token
   */
  public static refreshTokenBlacklistKey(jti: string): string {
    return `${RedisPrefix.REFRESH_TOKEN_BLACKLIST}${jti}`
  }

  /**
   * Tạo key cho refresh token đã được sử dụng
   * @param jti JWT ID của token
   */
  public static refreshTokenUsedKey(jti: string): string {
    return `${RedisPrefix.REFRESH_TOKEN_USED}${jti}`
  }

  /**
   * Tạo key cho OTP
   * @param type Loại OTP
   * @param identifier Định danh (email hoặc userId)
   */
  public static otpKey(type: string, identifier: string): string {
    return `${RedisPrefix.OTP}${type}:${identifier}`
  }

  /**
   * Tạo key cho thời gian gửi OTP gần nhất
   * @param identifier Định danh
   * @param purpose Mục đích của OTP
   */
  public static otpLastSentKey(identifier: string, purpose: string): string {
    return `${RedisPrefix.OTP_LAST_SENT}${purpose}:${identifier}`
  }

  /**
   * Tạo key cho context của SLT (Short-Lived Token)
   * @param jti JWT ID của token
   */
  public static sltContextKey(jti: string): string {
    return `${RedisPrefix.SLT_CONTEXT}${jti}`
  }

  /**
   * Tạo key cho blacklist của SLT
   * @param jti JWT ID của token
   */
  public static sltBlacklistKey(jti: string): string {
    return `${RedisPrefix.SLT_BLACKLIST}${jti}`
  }

  /**
   * Tạo key cho user bị vô hiệu hóa
   * @param userId ID của người dùng
   */
  public static invalidatedUserKey(userId: number): string {
    return `${RedisPrefix.INVALIDATED_USER}${userId}`
  }

  /**
   * Tạo key cache
   * @param key Khóa cache
   */
  public static cacheKey(key: string): string {
    return `${RedisPrefix.CACHE}${key}`
  }

  /**
   * Phương thức tạo key tùy chỉnh
   * @param prefix Prefix của key
   * @param parts Các phần của key
   */
  public static customKey(prefix: string, ...parts: (string | number)[]): string {
    return `${prefix}${parts.join(':')}`
  }

  /**
   * Tạo key cho lịch sử hoạt động của người dùng
   * @param userId ID của người dùng
   */
  public static userActivityKey(userId: number): string {
    return `${RedisPrefix.USER_ACTIVITY}${userId}:activities`
  }

  public static loginFailuresKey(userId: number): string {
    return `${RedisPrefix.LOGIN_FAILURES}${userId}`
  }

  public static lastLoginKey(userId: number): string {
    return `${RedisPrefix.LAST_LOGIN}${userId}`
  }

  public static passwordChangesKey(userId: number): string {
    return `${RedisPrefix.PASSWORD_CHANGES}${userId}`
  }

  public static accountLockKey(userId: number): string {
    return `${RedisPrefix.ACCOUNT_LOCK}${userId}`
  }

  public static suspiciousActivityNotificationKey(userId: number, ruleType: string): string {
    return `${RedisPrefix.SUSPICIOUS_NOTIFICATION}${userId}:${ruleType}`
  }
}
