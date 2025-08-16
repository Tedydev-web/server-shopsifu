import { registerAs } from '@nestjs/config'
import ms from 'ms'

export default registerAs(
  'cookie',
  (): Record<string, any> => ({
    accessToken: {
      name: 'access_token',
      options: {
        httpOnly: true,
        // Mặc định secure=true ở production, có thể override bằng COOKIE_SECURE
        secure: ((process.env.COOKIE_SECURE ?? process.env.NODE_ENV !== 'development') ? 'true' : 'false') === 'true',
        sameSite: 'none',
        path: process.env.COOKIE_ACCESS_TOKEN_PATH ?? '/',
        // Bỏ qua domain nếu giá trị không hợp lệ (ví dụ '/') để tránh lỗi "option domain is invalid"
        domain:
          process.env.COOKIE_ACCESS_TOKEN_DOMAIN && process.env.COOKIE_ACCESS_TOKEN_DOMAIN !== '/'
            ? process.env.COOKIE_ACCESS_TOKEN_DOMAIN
            : undefined,
        maxAge: ms(process.env.AUTH_ACCESS_TOKEN_EXP || '1d') // Provide a default value
      }
    },

    refreshToken: {
      name: 'refresh_token',
      options: {
        httpOnly: true,
        secure: ((process.env.COOKIE_SECURE ?? process.env.NODE_ENV !== 'development') ? 'true' : 'false') === 'true',
        sameSite: 'none',
        path: process.env.COOKIE_REFRESH_TOKEN_PATH ?? '/',
        domain:
          process.env.COOKIE_REFRESH_TOKEN_DOMAIN && process.env.COOKIE_REFRESH_TOKEN_DOMAIN !== '/'
            ? process.env.COOKIE_REFRESH_TOKEN_DOMAIN
            : undefined,
        maxAge: ms(process.env.AUTH_REFRESH_TOKEN_EXP || '7d') // Provide a default value
      }
    },

    csrfToken: {
      name: 'csrf_token',
      options: {
        httpOnly: false,
        secure: ((process.env.COOKIE_SECURE ?? process.env.NODE_ENV !== 'development') ? 'true' : 'false') === 'true',
        sameSite: 'none',
        path: process.env.COOKIE_CSRF_TOKEN_PATH ?? '/',
        domain:
          process.env.COOKIE_CSRF_TOKEN_DOMAIN && process.env.COOKIE_CSRF_TOKEN_DOMAIN !== '/'
            ? process.env.COOKIE_CSRF_TOKEN_DOMAIN
            : undefined,
        maxAge: ms(process.env.COOKIE_CSRF_TOKEN_EXP || '1h') // Provide a default value
      }
    }
  })
)
