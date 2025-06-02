/**
 * Auth Constants
 */

export enum AuthType {
  JWT = 'JWT',
  ApiKey = 'ApiKey',
  Basic = 'Basic',
  Bearer = 'Bearer',
  None = 'None'
}

export type AuthTypeType = (typeof AuthType)[keyof typeof AuthType]

export enum ConditionGuard {
  PassThrough = 'PassThrough',
  IsPublic = 'IsPublic',
  RolesOnly = 'RolesOnly',
  PermissionsOnly = 'PermissionsOnly',
  RolesAndPermissions = 'RolesAndPermissions',
  And = 'And'
}

export type ConditionGuardType = (typeof ConditionGuard)[keyof typeof ConditionGuard]

export enum CookieNames {
  ACCESS_TOKEN = 'access_token',
  REFRESH_TOKEN = 'refresh_token',
  SLT_TOKEN = 'slt_token',
  XSRF_TOKEN = 'xsrf-token',
  OAUTH_NONCE = 'oauth_nonce',
  OAUTH_PENDING_LINK = 'oauth_pending_link',
  NOTIFICATION_CONSENT = 'notification_consent'
}

export type CookieNamesType = (typeof CookieNames)[keyof typeof CookieNames]

/**
 * Security Headers
 */
export enum SecurityHeaders {
  XSRF_TOKEN_HEADER = 'xsrf-token',
  XSS_PROTECTION = 'X-XSS-Protection',
  CONTENT_TYPE_OPTIONS = 'X-Content-Type-Options',
  FRAME_OPTIONS = 'X-Frame-Options',
  HSTS = 'Strict-Transport-Security',
  CONTENT_SECURITY_POLICY = 'Content-Security-Policy',
  CACHE_CONTROL = 'Cache-Control',
  REFERRER_POLICY = 'Referrer-Policy',
  PERMITTED_CROSS_DOMAIN_POLICIES = 'X-Permitted-Cross-Domain-Policies',
  EXPECT_CT = 'Expect-CT'
}

export const REQUEST_USER_KEY = 'user'
