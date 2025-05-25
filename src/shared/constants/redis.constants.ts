export const REDIS_KEY_PREFIX = {
  USER_SESSIONS: 'user_sessions:', // Set: user:{userId}:sessions -> Set<sessionId>
  SESSION_DETAILS: 'session_details:', // Hash: session:{sessionId} -> SessionDetails
  REFRESH_TOKEN_JTI_TO_SESSION: 'rt_jti_session:', // String: rt-jti:{refreshTokenJti} -> sessionId
  ACCESS_TOKEN_BLACKLIST: 'bl_at:', // String: bl:at:{jti} -> "revoked" (with TTL)
  REFRESH_TOKEN_BLACKLIST: 'bl_rt:', // String: bl:rt:{jti} -> "revoked" (with TTL)
  OTP_STORE: 'otp:', // Hash: otp:{type}:{identifier} -> OtpDetails
  TOKEN_2FA_SETUP: 'token_2fa_setup:', // Hash: token:2fa-setup:{token} -> SetupDetails
  TOKEN_LOGIN_SESSION: 'token_login_session:', // Hash: token:login-session:{token} -> LoginSessionDetails
  RATE_LIMIT: 'rl:', // Counter: rl:{action}:{identifier}
  DEVICE_REFRESH_TOKENS: 'device_refresh_tokens:', // Set: device:{deviceId}:refreshTokens -> Set<refreshTokenJti>
  USER_KNOWN_LOCATIONS: 'user_known_locations:' // Added for tracking known user login locations
}
