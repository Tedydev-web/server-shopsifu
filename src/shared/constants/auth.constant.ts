export const REQUEST_USER_KEY = 'user'

export const AuthType = {
  Bearer: 'Bearer',
  None: 'None',
  APIKey: 'ApiKey'
} as const

export type AuthTypeType = (typeof AuthType)[keyof typeof AuthType]

export const ConditionGuard = {
  And: 'and',
  Or: 'or'
} as const

export type ConditionGuardType = (typeof ConditionGuard)[keyof typeof ConditionGuard]

export const CookieNames = {
  ACCESS_TOKEN: 'access_token',
  REFRESH_TOKEN: 'refresh_token',
  CSRF_TOKEN: 'xsrf-token',
  SLT_TOKEN: 'slt_token'
} as const

export type CookieNamesType = (typeof CookieNames)[keyof typeof CookieNames]

export const SecurityHeaders = {
  CSRF_TOKEN_HEADER: 'x-csrf-token',
  CONTENT_SECURITY_POLICY: 'Content-Security-Policy',
  X_CONTENT_TYPE_OPTIONS: 'X-Content-Type-Options',
  STRICT_TRANSPORT_SECURITY: 'Strict-Transport-Security',
  X_FRAME_OPTIONS: 'X-Frame-Options',
  X_XSS_PROTECTION: 'X-XSS-Protection',
  CACHE_CONTROL: 'Cache-Control'
} as const
