export const REDIS_KEY_PREFIX = {
  USER_SESSIONS: 'u_s:', // Set: u_s:{userId} -> sessionId
  SESSION_DETAILS: 'sess_d:', // Hash: sess_d:{sessionId} -> session details
  REFRESH_TOKEN_JTI_TO_SESSION: 'rt_jti_s:', // String: rt_jti_s:{refreshTokenJti} -> sessionId
  ACCESS_TOKEN_BLACKLIST: 'bl_at:', // String: bl_at:{jti} -> "revoked" (with TTL)
  REFRESH_TOKEN_BLACKLIST: 'bl_rt:', // String: bl_rt:{jti} -> "revoked" (with TTL) // Potentially deprecated by USED_REFRESH_TOKEN_JTI
  USED_REFRESH_TOKEN_JTI: 'used_rt_jti:', // String: used_rt_jti:{refreshTokenJti} -> "invalidated:{reason}" (with TTL)
  OTP_STORE: 'otp:', // String: otp:{type}:{email_or_phone} -> otp_code (with TTL)
  TOKEN_2FA_SETUP: 'tkn_2fa_setup:', // String: tkn_2fa_setup:{userId} -> setup_token (with TTL)
  TOKEN_LOGIN_SESSION: 'tkn_login_sess:', // String: tkn_login_sess:{userId} -> login_session_token (with TTL)
  RATE_LIMIT: 'rl:', // KV for rate limiting
  DEVICE_REFRESH_TOKENS: 'dev_rt:', // Set: dev_rt:{deviceId} -> refreshTokenJti (Deprecated or review usage)
  USER_KNOWN_LOCATIONS: 'usr_loc:' // Set: usr_loc:{userId} -> hashed_location_string
} as const
