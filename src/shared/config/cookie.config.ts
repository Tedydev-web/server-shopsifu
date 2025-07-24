import { registerAs } from '@nestjs/config'
import ms from 'ms'

export default registerAs(
  'cookie',
  (): Record<string, any> => ({
    // Cookie cho Access Token
    accessToken: {
      name: 'access_token',
      options: {
        httpOnly: 'true',
        secure: 'false',
        sameSite: 'none',
        path: process.env.COOKIE_ACCESS_TOKEN_PATH || '/',
        domain: process.env.COOKIE_ACCESS_TOKEN_DOMAIN || undefined,
        maxAge: ms(process.env.AUTH_ACCESS_TOKEN_EXP || '1d') // 1 ngày mặc định
      }
    },

    // Cookie cho Refresh Token
    refreshToken: {
      name: 'refresh_token',
      options: {
        httpOnly: 'true',
        secure: 'false',
        sameSite: 'none',
        path: process.env.COOKIE_REFRESH_TOKEN_PATH || '/',
        domain: process.env.COOKIE_REFRESH_TOKEN_DOMAIN || undefined,
        maxAge: ms(process.env.AUTH_REFRESH_TOKEN_EXP || '7d') // 7 ngày mặc định
      }
    },

    // Cookie cho CSRF Token
    csrfToken: {
      name: 'csrf_token',
      options: {
        httpOnly: 'false',
        secure: 'false',
        sameSite: 'none',
        path: '/',
        domain: undefined,
        maxAge: ms(process.env.AUTH_CSRF_TOKEN_EXP || '1h') // 1 giờ default
      }
    }
  })
)
