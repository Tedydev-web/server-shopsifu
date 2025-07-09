export const enum CookieNames {
  ACCESS_TOKEN = 'access_token',
  REFRESH_TOKEN = 'refresh_token',
  CSRF_SECRET = '_csrf',
  CSRF_TOKEN = 'csrf_token',
  SESSION = 'connect.sid'
}

const IS_PRODUCTION = process.env.NODE_ENV === 'production'

// Tùy chọn cơ bản cho tất cả cookie
const baseOptions = {
  secure: IS_PRODUCTION,
  sameSite: 'lax' as const,
  path: '/'
}

export const COOKIE_DEFINITIONS = {
  accessToken: {
    name: CookieNames.ACCESS_TOKEN,
    options: {
      ...baseOptions,
      httpOnly: false,
      secure: true,
      sameSite: 'none',
      // signed: true,
      maxAge: 15 * 60 * 1000 // 15 phút
    }
  },
  refreshToken: {
    name: CookieNames.REFRESH_TOKEN,
    options: {
      ...baseOptions,
      httpOnly: false, // Secret phải là httpOnly
      secure: true,
      sameSite: 'none',
      // signed: true,
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 ngày
    }
  },
  // Cookie chứa CSRF secret, được quản lý bởi thư viện csrf-csrf
  csrfSecret: {
    name: CookieNames.CSRF_TOKEN,
    options: {
      ...baseOptions,
      httpOnly: false, // Secret phải là httpOnly
      secure: true,
      sameSite: 'none',
      signed: false // Thư viện tự quản lý, không cần ký bằng cookie-parser
    }
  },
  // Cấu hình cho express-session
  session: {
    name: CookieNames.SESSION,
    options: {
      ...baseOptions,
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000 // 24 giờ
    }
  }
} as const

export type CookieDefinitionKey = keyof typeof COOKIE_DEFINITIONS
