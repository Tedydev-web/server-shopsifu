import z from 'zod'
import fs from 'fs'
import path from 'path'
import { config } from 'dotenv'
import ms from 'ms'

config({
  path: '.env'
})
// Kiểm tra coi thử có file .env hay chưa
if (!fs.existsSync(path.resolve('.env'))) {
  console.log('Không tìm thấy file .env')
  process.exit(1)
}

const configSchema = z.object({
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  DATABASE_URL: z.string(),
  ACCESS_TOKEN_SECRET: z.string(),
  ACCESS_TOKEN_EXPIRES_IN: z.string(),
  REFRESH_TOKEN_SECRET: z.string(),
  REFRESH_TOKEN_EXPIRES_IN: z.string(),
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
  APP_NAME: z.string(),
  LOGIN_SESSION_TOKEN_EXPIRES_IN: z.string(),
  OTP_TOKEN_EXPIRES_IN: z.string(),
  // Cookie config
  COOKIE_SECRET: z.string().default('shopsifu-cookie-secret'),
  COOKIE_DOMAIN: z.string().optional(),
  // CSRF config
  CSRF_SECRET: z.string().default('shopsifu-csrf-secret'),
  // Remember Me refresh token lifetimes
  REMEMBER_ME_REFRESH_TOKEN_EXPIRES_IN: z.string().default('30d')
})

const configServer = configSchema.safeParse(process.env)

if (!configServer.success) {
  console.log('Các giá trị khai báo trong file .env không hợp lệ')
  console.error(configServer.error)
  process.exit(1)
}

const envConfig = {
  ...configServer.data,
  // Cookie settings
  ACCESS_TOKEN_COOKIE_MAX_AGE: ms(configServer.data.ACCESS_TOKEN_EXPIRES_IN),
  REFRESH_TOKEN_COOKIE_MAX_AGE: ms(configServer.data.REFRESH_TOKEN_EXPIRES_IN),
  // Max age cho các loại refresh token
  REMEMBER_ME_REFRESH_TOKEN_COOKIE_MAX_AGE: ms(configServer.data.REMEMBER_ME_REFRESH_TOKEN_EXPIRES_IN)
}

console.log('[DEBUG] Loaded envConfig in config.ts:', {
  NODE_ENV: envConfig.NODE_ENV,
  ACCESS_TOKEN_EXPIRES_IN: envConfig.ACCESS_TOKEN_EXPIRES_IN,
  ACCESS_TOKEN_COOKIE_MAX_AGE: envConfig.ACCESS_TOKEN_COOKIE_MAX_AGE,
  REMEMBER_ME_REFRESH_TOKEN_EXPIRES_IN: envConfig.REMEMBER_ME_REFRESH_TOKEN_EXPIRES_IN,
  REMEMBER_ME_REFRESH_TOKEN_COOKIE_MAX_AGE: envConfig.REMEMBER_ME_REFRESH_TOKEN_COOKIE_MAX_AGE,
  REFRESH_TOKEN_EXPIRES_IN: envConfig.REFRESH_TOKEN_EXPIRES_IN,
  REFRESH_TOKEN_COOKIE_MAX_AGE: envConfig.REFRESH_TOKEN_COOKIE_MAX_AGE,
  COOKIE_SECRET_LOADED: !!envConfig.COOKIE_SECRET,
  CSRF_SECRET_LOADED: !!envConfig.CSRF_SECRET
})

export default envConfig
