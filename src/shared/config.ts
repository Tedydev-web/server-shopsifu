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
  CSRF_SECRET: z.string().default('shopsifu-csrf-secret')
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
  REFRESH_TOKEN_COOKIE_MAX_AGE: ms(configServer.data.REFRESH_TOKEN_EXPIRES_IN)
}

export default envConfig
