import { z } from 'zod'
import ms from 'ms'
import { config } from 'dotenv'
import { CookieNames } from './constants/cookie.constant'
import fs from 'fs'
import path from 'path'

// Load environment variables
config({
  path: '.env'
})
// Kiểm tra coi thử có file .env hay chưa
if (!fs.existsSync(path.resolve('.env'))) {
  console.log('Không tìm thấy file .env')
  process.exit(1)
}

// ==================== VALIDATION SCHEMAS ====================

const configSchema = z.object({
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  PORT: z.coerce.number().int().positive().min(1).max(65535).default(3000),
  APP_NAME: z.string().min(1).max(100).default('Shopsifu'),
  PAYMENT_API_KEY: z.string().min(32).max(128),
  CLIENT_URL: z.string().url(),
  EMAIL_FROM: z.string().email().default('noreply@shopsifu.com'),
  LOG_LEVEL: z.enum(['error', 'warn', 'info', 'debug']).default('info'),
  CSRF_SECRET_LENGTH: z.coerce.number().int().positive().min(16).max(64).default(32),
  CSRF_HEADER_NAME: z.string().min(1).max(50).default('x-csrf-token'),
  COOKIE_SECRET: z.string().min(32).max(128),
  RATE_LIMIT_WINDOW_MS: z.coerce
    .number()
    .int()
    .positive()
    .default(15 * 60 * 1000), // 15 minutes
  RATE_LIMIT_MAX_REQUESTS: z.coerce.number().int().positive().default(100),
  ACCESS_TOKEN_SECRET: z.string().min(32).max(512),
  ACCESS_TOKEN_EXPIRES_IN: z
    .string()
    .regex(/^\d+[mhd]$/)
    .default('15m'),
  REFRESH_TOKEN_SECRET: z.string().min(32).max(512),
  REFRESH_TOKEN_EXPIRES_IN: z
    .string()
    .regex(/^\d+[mhd]$/)
    .default('7d'),
  JWT_ISSUER: z.string().default('shopsifu'),
  JWT_AUDIENCE: z.string().default('shopsifu-users'),
  DATABASE_URL: z.string().url(),
  DATABASE_POOL_MIN: z.coerce.number().int().positive().default(2),
  DATABASE_POOL_MAX: z.coerce.number().int().positive().default(10),
  DATABASE_TIMEOUT: z.coerce.number().int().positive().default(30000),
  REDIS_HOST: z.string().default('localhost'),
  REDIS_PORT: z.coerce.number().int().positive().min(1).max(65535).default(6379),
  REDIS_PASSWORD: z.string().optional(),
  REDIS_DB: z.coerce.number().int().min(0).max(15).default(0),
  REDIS_TTL: z.coerce.number().int().positive().default(3600), // 1 hour
  REDIS_MAX_RETRIES: z.coerce.number().int().positive().default(3),
  EMAIL_API_KEY: z.string().min(32).max(128),
  EMAIL_FROM_NAME: z.string().default('Shopsifu Team'),
  EMAIL_TEMPLATE_DIR: z.string().default('./emails'),
  EMAIL_RATE_LIMIT: z.coerce.number().int().positive().default(10), // emails per minute
  GOOGLE_CLIENT_ID: z.string().min(20).max(200),
  GOOGLE_CLIENT_SECRET: z.string().min(20).max(200),
  GOOGLE_REDIRECT_URI: z.string().url(),
  GOOGLE_SCOPE: z.string().default('email profile'),
  UPLOAD_MAX_SIZE: z.coerce
    .number()
    .int()
    .positive()
    .default(10 * 1024 * 1024), // 10MB
  UPLOAD_ALLOWED_TYPES: z.string().default('image/jpeg,image/png,image/webp'),
  UPLOAD_DIR: z.string().default('./upload'),
  STATIC_URL_PREFIX: z.string().default('/media/static'),
  CDN_URL: z.string().url().optional(),
  S3_REGION: z.string().min(1).max(50),
  S3_ACCESS_KEY: z.string().min(20).max(100),
  S3_SECRET_KEY: z.string().min(20).max(100),
  S3_BUCKET_NAME: z.string().min(1).max(63),
  S3_ENDPOINT: z.string().url().optional(),
  S3_FORCE_PATH_STYLE: z.coerce.boolean().default(false),
  ADMIN_NAME: z.string().min(1).max(100),
  ADMIN_PASSWORD: z.string().min(8).max(128),
  ADMIN_EMAIL: z.string().email(),
  ADMIN_PHONE_NUMBER: z.string().regex(/^\+?[\d\s\-()]+$/),
  ENABLE_2FA: z.coerce.boolean().default(true),
  ENABLE_SOCIAL_LOGIN: z.coerce.boolean().default(true),
  ENABLE_DEVICE_TRACKING: z.coerce.boolean().default(true),
  ENABLE_AUDIT_LOG: z.coerce.boolean().default(true),
  DEVICE_TRUST_EXPIRATION_DAYS: z.coerce.number().int().positive().default(30),
  SESSION_TIMEOUT_MINUTES: z.coerce.number().int().positive().default(30),
  OTP_EXPIRES_IN: z.coerce
    .number()
    .int()
    .positive()
    .default(15 * 60 * 1000)
})

// ==================== VALIDATION ====================

const configServer = configSchema.safeParse(process.env)

if (!configServer.success) {
  console.log('Các giá trị khai báo trong file .env không hợp lệ')
  console.error(configServer.error)
  process.exit(1)
}

const envConfig = configServer.data

export default envConfig
