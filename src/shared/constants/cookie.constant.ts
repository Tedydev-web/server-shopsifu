export const enum CookieNames {
  ACCESS_TOKEN = 'access_token',
  REFRESH_TOKEN = 'refresh_token',
  CSRF_SECRET = '_csrf',
  CSRF_TOKEN = 'XSRF-TOKEN',
  SLT = 'slt'
}

export const COOKIE_DEFINITIONS = {
  accessToken: {
    name: CookieNames.ACCESS_TOKEN,
    prefix: '',
    options: {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax' as const,
      path: '/',
      signed: true,
      maxAge: 15 * 60 * 1000 // 15 minutes
    }
  },
  refreshToken: {
    name: CookieNames.REFRESH_TOKEN,
    prefix: '',
    options: {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax' as const,
      path: '/',
      signed: true,
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    }
  },
  csrfToken: {
    name: CookieNames.CSRF_TOKEN,
    prefix: '',
    options: {
      httpOnly: false,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax' as const,
      path: '/',
      signed: false
    }
  },
  slt: {
    name: CookieNames.SLT,
    prefix: '',
    options: {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax' as const,
      path: '/',
      signed: true
    }
  }
} as const

export type CookieDefinitionKey = keyof typeof COOKIE_DEFINITIONS
