import { registerAs } from '@nestjs/config'
import ms from 'ms'

const IS_PRODUCTION = process.env.NODE_ENV === 'production'

export default registerAs(
  'cookie',
  (): Record<string, any> => ({
    // Cookie cho Access Token
    accessToken: {
      name: 'access_token',
      options: {
        httpOnly: process.env.COOKIE_ACCESS_TOKEN_HTTP_ONLY === 'true' || IS_PRODUCTION,
        secure: process.env.COOKIE_ACCESS_TOKEN_SECURE === 'true' || IS_PRODUCTION,
        sameSite:
          (process.env.COOKIE_ACCESS_TOKEN_SAME_SITE as 'strict' | 'lax' | 'none') ||
          (IS_PRODUCTION ? 'strict' : 'lax'),
        path: process.env.COOKIE_ACCESS_TOKEN_PATH || '/',
        domain: process.env.COOKIE_ACCESS_TOKEN_DOMAIN || undefined,
        maxAge: ms(process.env.AUTH_ACCESS_TOKEN_EXP || '1d') // 1 ngày mặc định
      }
    },

    // Cookie cho Refresh Token
    refreshToken: {
      name: 'refresh_token',
      options: {
        httpOnly: process.env.COOKIE_REFRESH_TOKEN_HTTP_ONLY === 'true' || true, // Luôn httpOnly cho refresh token
        secure: process.env.COOKIE_REFRESH_TOKEN_SECURE === 'true' || IS_PRODUCTION,
        sameSite:
          (process.env.COOKIE_REFRESH_TOKEN_SAME_SITE as 'strict' | 'lax' | 'none') ||
          (IS_PRODUCTION ? 'strict' : 'lax'),
        path: process.env.COOKIE_REFRESH_TOKEN_PATH || '/',
        domain: process.env.COOKIE_REFRESH_TOKEN_DOMAIN || undefined,
        maxAge: ms(process.env.AUTH_REFRESH_TOKEN_EXP || '7d') // 7 ngày mặc định
      }
    },

    // Cookie cho CSRF Token
    csrfToken: {
      name: process.env.COOKIE_CSRF_TOKEN_NAME || 'csrf_token',
      options: {
        httpOnly: process.env.COOKIE_CSRF_TOKEN_HTTP_ONLY === 'true' || false, // CSRF token cần access bằng JavaScript
        secure: process.env.COOKIE_CSRF_TOKEN_SECURE === 'true' || IS_PRODUCTION,
        sameSite:
          (process.env.COOKIE_CSRF_TOKEN_SAME_SITE as 'strict' | 'lax' | 'none') || (IS_PRODUCTION ? 'strict' : 'lax'),
        path: process.env.COOKIE_CSRF_TOKEN_PATH || '/',
        domain: process.env.COOKIE_CSRF_TOKEN_DOMAIN || undefined,
        maxAge: ms(process.env.AUTH_CSRF_TOKEN_EXP || '1h') // 1 giờ default
      }
    }
  })
)
