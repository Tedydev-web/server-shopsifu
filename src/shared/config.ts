import z from 'zod'
import fs from 'fs'
import path from 'path'
import { config } from 'dotenv'

config({
  path: '.env'
})
// Kiểm tra coi thử có file .env hay chưa
if (!fs.existsSync(path.resolve('.env'))) {
  console.log('Không tìm thấy file .env')
  process.exit(1)
}

const configSchema = z.object({
  // Application settings
  NODE_ENV: z.string(),
  APP_NAME: z.string(),
  APP_DEBUG: z.coerce.boolean(),
  APP_LOG_LEVEL: z.string(),
  APP_CORS_ORIGINS: z.string(),

  // HTTP Server configuration
  HTTP_HOST: z.string(),
  HTTP_PORT: z.coerce.number().int().positive(),
  HTTP_VERSIONING_ENABLE: z.coerce.boolean(),
  HTTP_VERSION: z.coerce.number().int().positive(),

  // Error tracking - Sentry
  SENTRY_DSN: z.string().url().optional(),

  // Authentication & JWT
  AUTH_ACCESS_TOKEN_SECRET: z.string().min(32),
  AUTH_REFRESH_TOKEN_SECRET: z.string().min(32),
  AUTH_ACCESS_TOKEN_EXP: z.string(),
  AUTH_REFRESH_TOKEN_EXP: z.string(),

  // Database configuration
  DATABASE_URL: z.string().url(),

  // OTP configuration
  OTP_EXP: z.string(),

  // Cookie configuration
  COOKIE_SECRET: z.string().min(32),

  // Google Auth configuration
  GOOGLE_CLIENT_ID: z.string(),
  GOOGLE_CLIENT_SECRET: z.string(),
  GOOGLE_CLIENT_REDIRECT_URI: z.string().url(),
  GOOGLE_REDIRECT_URI: z.string().url(),

  // Admin configuration
  ADMIN_NAME: z.string(),
  ADMIN_PASSWORD: z.string().min(8),
  ADMIN_EMAIL: z.string().email(),
  ADMIN_PHONE_NUMBER: z.string().min(9).max(15),

  // Resend API key configuration
  RESEND_API_KEY: z.string(),

  // AWS configuration
  AWS_ACCESS_KEY: z.string(),
  AWS_SECRET_KEY: z.string(),
  AWS_REGION: z.string(),

  // AWS S3 configuration
  S3_ACCESS_KEY: z.string(),
  S3_SECRET_KEY: z.string(),
  AWS_PRESIGN_LINK_EXPIRES: z.coerce.number().int().positive(),
  S3_BUCKET_NAME: z.string(),

  // Prefix static endpoint configuration
  PREFIX_STATIC_ENPOINT: z.string().url(),

  // Redis configuration
  REDIS_HOST: z.string(),
  REDIS_PORT: z.coerce.number().int().positive(),
  REDIS_PASSWORD: z.string(),
  REDIS_ENABLE_TLS: z.coerce.boolean(),
  REDIS_URL: z.string().url(),

  // Payment API key configuration
  PAYMENT_API_KEY: z.string()
})

const configServer = configSchema.safeParse(process.env)

if (!configServer.success) {
  console.log('Các giá trị khai báo trong file .env không hợp lệ')
  console.error(configServer.error)
  process.exit(1)
}

const envConfig = configServer.data

export default envConfig
