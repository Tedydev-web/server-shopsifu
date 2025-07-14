import envConfig from '../config'
import ms from 'ms'

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

// Helper function để chuyển đổi string thành milliseconds
const parseMs = (value: string): number => {
  return (ms as any)(value)
}

export const COOKIE_DEFINITIONS = {
  accessToken: {
    name: CookieNames.ACCESS_TOKEN,
    options: {
      ...baseOptions,
      httpOnly: false,
      secure: true,
      sameSite: 'none' as const,
      // signed: true,
      maxAge: parseMs(process.env.AUTH_ACCESS_TOKEN_EXP)
    }
  },
  refreshToken: {
    name: CookieNames.REFRESH_TOKEN,
    options: {
      ...baseOptions,
      httpOnly: false, // Secret phải là httpOnly
      secure: true,
      sameSite: 'none' as const,
      // signed: true,
      maxAge: parseMs(process.env.AUTH_REFRESH_TOKEN_EXP)
    }
  },
  // Cookie chứa CSRF secret, được quản lý bởi thư viện csrf-csrf
  csrfSecret: {
    name: CookieNames.CSRF_TOKEN,
    options: {
      ...baseOptions,
      httpOnly: false, // Secret phải là httpOnly
      secure: true,
      sameSite: 'none' as const,
      signed: false // Thư viện tự quản lý, không cần ký bằng cookie-parser
    }
  },
  // Cấu hình cho express-session - session nên có thời gian hết hạn dài hơn RT một chút
  session: {
    name: CookieNames.SESSION,
    options: {
      ...baseOptions,
      httpOnly: true,
      maxAge: parseMs(process.env.AUTH_REFRESH_TOKEN_EXP) + parseMs('1d') // RT + 1 ngày
    }
  }
} as const

export type CookieDefinitionKey = keyof typeof COOKIE_DEFINITIONS
