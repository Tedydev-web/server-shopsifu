export const enum CookieNames {
  ACCESS_TOKEN = 'access_token',
  REFRESH_TOKEN = 'refresh_token',
  CSRF_TOKEN = 'csrf_token',
  SESSION = 'connect.sid', // Tên mặc định cho express-session
  SLT = 'slt'
}

const IS_PRODUCTION = process.env.NODE_ENV === 'production'

// Tùy chọn cơ bản cho tất cả cookie
const baseOptions = {
  secure: IS_PRODUCTION,
  sameSite: 'lax' as const,
  path: '/'
}

// Tùy chọn cho cookie cần ký và httpOnly
const signedHttpOnlyOptions = {
  ...baseOptions,
  httpOnly: true,
  signed: true
}

export const COOKIE_DEFINITIONS = {
  accessToken: {
    name: CookieNames.ACCESS_TOKEN,
    options: {
      ...signedHttpOnlyOptions,
      httpOnly: false, // Secret phải là httpOnly
      secure: true,
      sameSite: 'none',
      maxAge: 15 * 60 * 1000 // 15 phút
    }
  },
  refreshToken: {
    name: CookieNames.REFRESH_TOKEN,
    options: {
      ...signedHttpOnlyOptions,
      httpOnly: false, // Secret phải là httpOnly
      secure: true,
      sameSite: 'none',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 ngày
    }
  },
  // Cookie chứa CSRF token để client-side script đọc
  csrfToken: {
    name: CookieNames.CSRF_TOKEN,
    options: {
      ...baseOptions,
      httpOnly: false,
      signed: false // Không cần ký vì đây là token, không phải secret
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
  slt: {
    name: CookieNames.SLT,
    options: {
      ...signedHttpOnlyOptions
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
