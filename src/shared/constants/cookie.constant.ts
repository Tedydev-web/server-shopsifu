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
      secure: process.env.NODE_ENV !== 'development',
      sameSite: 'lax',
      path: '/',
      signed: true
    }
  },
  refreshToken: {
    name: CookieNames.REFRESH_TOKEN,
    prefix: '',
    options: {
      httpOnly: true,
      secure: process.env.NODE_ENV !== 'development',
      sameSite: 'lax',
      path: '/',
      signed: true
    }
  },
  csrfToken: {
    name: CookieNames.CSRF_TOKEN,
    prefix: '',
    options: {
      httpOnly: false,
      secure: process.env.NODE_ENV !== 'development',
      sameSite: 'lax',
      path: '/',
      signed: false
    }
  },
  slt: {
    name: CookieNames.SLT,
    prefix: '',
    options: {
      httpOnly: true,
      secure: process.env.NODE_ENV !== 'development',
      sameSite: 'lax',
      path: '/',
      signed: true
    }
  }
} as const

export type CookieDefinitionKey = keyof typeof COOKIE_DEFINITIONS
