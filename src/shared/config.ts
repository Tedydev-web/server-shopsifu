import z from 'zod'
import fs from 'fs'
import path from 'path'
import { config } from 'dotenv'
import ms from 'ms'
import { CookieNames } from 'src/shared/constants/auth.constant'

config({
  path: '.env'
})

if (!fs.existsSync(path.resolve('.env'))) {
  console.log('Không tìm thấy file .env')
  process.exit(1)
}

const configSchema = z.object({
  NODE_ENV: z.enum(['development', 'production', 'test', 'staging']).default('development'),
  DATABASE_URL: z.string(),
  ACCESS_TOKEN_SECRET: z.string(),
  ACCESS_TOKEN_EXPIRES_IN: z.string().default('10m'),
  REFRESH_TOKEN_SECRET: z.string(),
  REFRESH_TOKEN_EXPIRES_IN: z.string().default('1d'),
  SECRET_API_KEY: z.string(),
  ADMIN_NAME: z.string(),
  ADMIN_PASSWORD: z.string(),
  ADMIN_EMAIL: z.string(),
  ADMIN_PHONE_NUMBER: z.string(),
  RESEND_API_KEY: z.string(),
  GOOGLE_CLIENT_ID: z.string(),
  GOOGLE_CLIENT_SECRET: z.string(),
  GOOGLE_REDIRECT_URI: z.string(),
  GOOGLE_CLIENT_REDIRECT_URI: z.string(),
  APP_NAME: z.string().default('Shopsifu'),
  LOGIN_SESSION_TOKEN_EXPIRES_IN: z.string().default('15m'),
  OTP_TOKEN_EXPIRES_IN: z.string().default('15m'),
  COOKIE_SECRET: z.string(), // Used for signing cookies, including the CSRF secret cookie if not overridden
  COOKIE_ROOT_DOMAIN: z.string().optional(),
  CSRF_SECRET: z.string(), // Secret specifically for CSRF token generation and verification by csurf
  REMEMBER_ME_REFRESH_TOKEN_EXPIRES_IN: z.string().default('14d'),
  ABSOLUTE_SESSION_LIFETIME: z.string().default('30d'),
  API_HOST_URL: z.string(),
  API_LOCAL_URL: z.string(),
  FRONTEND_HOST_URL: z.string(),
  FRONTEND_LOCAL_URL: z.string(),
  PORT: z.string().default('3000'),

  COOKIE_PATH_ACCESS_TOKEN: z.string().default('/'),

  COOKIE_PATH_REFRESH_TOKEN: z.string().default('/'),
  COOKIE_PATH_CSRF: z.string().default('/'),

  // Redis Configuration
  REDIS_HOST: z.string().default('127.0.0.1'),
  REDIS_PORT: z.coerce.number().default(6379),
  REDIS_PASSWORD: z.string().optional().default(''), // Cung cấp giá trị mặc định là chuỗi rỗng
  REDIS_DB: z.coerce.number().default(0),
  REDIS_KEY_PREFIX: z.string().default('shopsifu:'),
  REDIS_DEFAULT_TTL_MS: z.coerce.number().default(60000),

  // Session and Device Limits
  MAX_ACTIVE_SESSIONS_PER_USER: z.coerce.number().int().positive().optional().default(10),
  MAX_DEVICES_PER_USER: z.coerce.number().int().positive().optional().default(5)
})

const configServer = configSchema.safeParse(process.env)

if (!configServer.success) {
  console.log('Các giá trị khai báo trong file .env không hợp lệ')
  console.error(configServer.error.format())
  process.exit(1)
}

const parsedConfig = configServer.data
const nodeEnv = parsedConfig.NODE_ENV

let cookieSecure: boolean
let cookieSameSite: 'lax' | 'strict' | 'none'
let cookieDomain: string | undefined

switch (nodeEnv) {
  case 'production':
    cookieSecure = true
    cookieSameSite = 'lax'
    cookieDomain = parsedConfig.COOKIE_ROOT_DOMAIN || undefined
    break
  case 'staging':
    cookieSecure = true
    cookieSameSite = 'none'
    cookieDomain = parsedConfig.COOKIE_ROOT_DOMAIN || undefined
    break
  case 'development':
  default:
    cookieSecure = false
    cookieSameSite = 'lax'
    cookieDomain = parsedConfig.COOKIE_ROOT_DOMAIN || 'localhost'
    break
}

const envConfig = {
  ...parsedConfig, // Các biến từ process.env đã được parse và validate, bao gồm cả Redis vars
  ACCESS_TOKEN_COOKIE_MAX_AGE: ms(parsedConfig.ACCESS_TOKEN_EXPIRES_IN),
  REFRESH_TOKEN_COOKIE_MAX_AGE: ms(parsedConfig.REFRESH_TOKEN_EXPIRES_IN),
  REMEMBER_ME_REFRESH_TOKEN_COOKIE_MAX_AGE: ms(parsedConfig.REMEMBER_ME_REFRESH_TOKEN_EXPIRES_IN),
  ABSOLUTE_SESSION_LIFETIME_MS: ms(parsedConfig.ABSOLUTE_SESSION_LIFETIME),

  cookie: {
    accessToken: {
      name: CookieNames.ACCESS_TOKEN,
      path: parsedConfig.COOKIE_PATH_ACCESS_TOKEN,
      domain: cookieDomain,
      maxAge: ms(parsedConfig.ACCESS_TOKEN_EXPIRES_IN),
      httpOnly: true,
      secure: cookieSecure,
      sameSite: cookieSameSite
    },
    refreshToken: {
      name: CookieNames.REFRESH_TOKEN,
      path: parsedConfig.COOKIE_PATH_REFRESH_TOKEN,
      domain: cookieDomain,
      maxAge: ms(parsedConfig.REFRESH_TOKEN_EXPIRES_IN),
      httpOnly: true,
      secure: cookieSecure,
      sameSite: cookieSameSite
    },
    csrfToken: {
      name: CookieNames.CSRF_TOKEN,
      path: parsedConfig.COOKIE_PATH_CSRF,
      domain: cookieDomain,
      httpOnly: false,
      secure: cookieSecure,
      sameSite: cookieSameSite
    },
    csrfSecret: {
      name: '_csrf',
      path: parsedConfig.COOKIE_PATH_CSRF,
      domain: cookieDomain,
      httpOnly: true,
      secure: cookieSecure,
      sameSite: cookieSameSite,
      signed: true
    }
  }
}

export default envConfig
