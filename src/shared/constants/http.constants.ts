export enum HttpHeader {
  // Security Headers
  XSS_PROTECTION = 'X-XSS-Protection',
  CONTENT_TYPE_OPTIONS = 'X-Content-Type-Options',
  FRAME_OPTIONS = 'X-Frame-Options',
  HSTS = 'Strict-Transport-Security',
  CACHE_CONTROL = 'Cache-Control',
  CONTENT_SECURITY_POLICY = 'Content-Security-Policy',
  PERMITTED_CROSS_DOMAIN_POLICIES = 'X-Permitted-Cross-Domain-Policies',
  EXPECT_CT = 'Expect-CT',
  REFERRER_POLICY = 'Referrer-Policy',
  // CSRF Headers (sử dụng trong csrf.middleware.ts và main.ts)
  XSRF_TOKEN_HEADER = 'X-XSRF-TOKEN', // Thường được Angular sử dụng
  CSRF_TOKEN_HEADER = 'X-CSRF-TOKEN', // Một tên phổ biến khác

  // Common Headers
  AUTHORIZATION = 'Authorization',
  CONTENT_TYPE = 'Content-Type',
  ACCEPT_LANGUAGE = 'Accept-Language',
  USER_AGENT = 'User-Agent',
  LOCATION = 'Location'
}

// Optional: Type for convenience if needed elsewhere
export type HttpHeaderType = (typeof HttpHeader)[keyof typeof HttpHeader]
