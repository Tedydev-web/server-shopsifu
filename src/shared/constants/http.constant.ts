export const HTTPMethod = {
  GET: 'GET',
  POST: 'POST',
  PUT: 'PUT',
  DELETE: 'DELETE',
  PATCH: 'PATCH',
  OPTIONS: 'OPTIONS',
  HEAD: 'HEAD'
} as const

export type HTTPMethodType = keyof typeof HTTPMethod

export const HTTPRequestHeaderKeys = {
  USER_AGENT: 'user-agent',
  AUTHORIZATION: 'authorization',
  CONTENT_TYPE: 'content-type',
  ACCEPT: 'accept',
  X_FORWARDED_FOR: 'x-forwarded-for'
  // Add other common request headers here as needed
} as const

/**
 * Standard HTTP Security Headers
 * These are common HTTP headers used to enhance application security.
 */
export enum SecurityHeaders {
  XSRF_TOKEN_HEADER = 'xsrf-token', // Commonly used for XSRF token
  CSRF_TOKEN_HEADER = 'x-csrf-token', // Alternative CSRF token header name
  XSS_PROTECTION = 'X-XSS-Protection', // Enables XSS filtering
  CONTENT_TYPE_OPTIONS = 'X-Content-Type-Options', // Prevents MIME-sniffing
  FRAME_OPTIONS = 'X-Frame-Options', // Protects against clickjacking
  HSTS = 'Strict-Transport-Security', // Enforces HTTPS
  CONTENT_SECURITY_POLICY = 'Content-Security-Policy', // Controls resources the browser is allowed to load
  CACHE_CONTROL = 'Cache-Control', // Directives for caching mechanisms in requests and responses
  REFERRER_POLICY = 'Referrer-Policy', // Controls how much referrer information is sent
  PERMITTED_CROSS_DOMAIN_POLICIES = 'X-Permitted-Cross-Domain-Policies', // Controls Flash content's access to data
  EXPECT_CT = 'Expect-CT' // For Certificate Transparency
}
