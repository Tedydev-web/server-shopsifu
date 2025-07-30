import { registerAs } from '@nestjs/config'
import ms from 'ms'

export default registerAs(
  'cookie',
  (): Record<string, any> => ({
    accessToken: {
      name: 'access_token',
      options: {
        httpOnly: 'true',
        secure: 'false',
        sameSite: 'none',
        path: process.env.COOKIE_ACCESS_TOKEN_PATH,
        domain: process.env.COOKIE_ACCESS_TOKEN_DOMAIN,
        maxAge: ms(process.env.AUTH_ACCESS_TOKEN_EXP)
      }
    },

    refreshToken: {
      name: 'refresh_token',
      options: {
        httpOnly: 'true',
        secure: 'false',
        sameSite: 'none',
        path: process.env.COOKIE_REFRESH_TOKEN_PATH,
        domain: process.env.COOKIE_REFRESH_TOKEN_DOMAIN,
        maxAge: ms(process.env.AUTH_REFRESH_TOKEN_EXP)
      }
    },

    csrfToken: {
      name: 'csrf_token',
      options: {
        httpOnly: 'false',
        secure: 'false',
        sameSite: 'none',
        path: process.env.COOKIE_CSRF_TOKEN_PATH,
        domain: process.env.COOKIE_CSRF_TOKEN_DOMAIN,
        maxAge: ms(process.env.COOKIE_CSRF_TOKEN_EXP)
      }
    }
  })
)
