import z from 'zod'
import fs from 'fs'
import path from 'path'
import { config } from 'dotenv'
import ms from 'ms'
import { CookieNames } from 'src/routes/auth/shared/constants/auth.constants'

// Load và kiểm tra file .env
config({ path: '.env' })

if (!fs.existsSync(path.resolve('.env'))) {
  console.log('Không tìm thấy file .env')
  process.exit(1)
}

/**
 * Schema validation cho biến môi trường
 */
const configSchema = z.object({
  // Server & môi trường
  NODE_ENV: z.enum(['development', 'production', 'test', 'staging']).default('development'),
  PORT: z.string().default('3000'),
  API_URL: z.string(),
  FRONTEND_URL: z.string(),
  APP_NAME: z.string().default('Shopsifu'),

  // Database
  DATABASE_URL: z.string(),

  // Cookie & Security
  COOKIE_SECRET: z.string(),
  CSRF_SECRET: z.string(),
  COOKIE_ROOT_DOMAIN: z.string().optional(),
  COOKIE_PATH_ACCESS_TOKEN: z.string().default('/'),
  COOKIE_PATH_REFRESH_TOKEN: z.string().default('/'),
  COOKIE_PATH_CSRF: z.string().default('/'),
  COOKIE_DOMAIN: z.string().optional(),
  COOKIE_HTTP_ONLY: z.boolean().default(false),
  COOKIE_SAME_SITE: z.enum(['lax', 'strict', 'none']).default('lax'),

  // Access & Refresh Token
  ACCESS_TOKEN_SECRET: z.string(),
  ACCESS_TOKEN_EXPIRES_IN: z.string().default('10m'),
  REFRESH_TOKEN_SECRET: z.string(),
  REFRESH_TOKEN_EXPIRES_IN: z.string().default('1d'),
  REMEMBER_ME_REFRESH_TOKEN_EXPIRES_IN: z.string().default('14d'),
  ABSOLUTE_SESSION_LIFETIME: z.string().default('30d'),
  LOGIN_SESSION_TOKEN_EXPIRES_IN: z.string().default('15m'),

  // OTP & Verification
  OTP_TOKEN_EXPIRES_IN: z.string().default('15m'),
  OTP_EXPIRES_IN: z.string().default('5m'),
  VERIFICATION_JWT_SECRET: z.string(),
  VERIFICATION_JWT_EXPIRES_IN: z.string().default('15m'),

  // SLT (State-Linking Token)
  SLT_JWT_SECRET: z.string(),
  SLT_JWT_EXPIRES_IN: z.string().default('5m'),

  // Auth - Pending link
  PENDING_LINK_TOKEN_SECRET: z.string(),
  PENDING_LINK_TOKEN_EXPIRES_IN: z.string().default('15m'),
  NONCE_COOKIE_MAX_AGE: z.string().optional(),
  EMAIL_VERIFICATION_TOKEN_EXPIRES_IN: z.string().default('15m'),

  // OAuth
  GOOGLE_CLIENT_ID: z.string(),
  GOOGLE_CLIENT_SECRET: z.string(),
  GOOGLE_REDIRECT_URI: z.string(),

  // Redis
  REDIS_HOST: z.string().default('redis-18980.c1.ap-southeast-1-1.ec2.redns.redis-cloud.com'),
  REDIS_PORT: z.coerce.number().default(18980),
  REDIS_PASSWORD: z.string().optional().default(''),
  REDIS_DB: z.coerce.number().default(0),
  REDIS_KEY_PREFIX: z.string().default('shopsifu:'),
  REDIS_DEFAULT_TTL_MS: z.coerce.number().default(60000),

  // Session & Device
  MAX_ACTIVE_SESSIONS_PER_USER: z.coerce.number().int().positive().optional().default(10),
  MAX_DEVICES_PER_USER: z.coerce.number().int().positive().optional().default(5),
  DEVICE_TRUST_EXPIRATION_DAYS: z.coerce.number().int().positive().optional().default(30),

  // Email
  RESEND_API_KEY: z.string(),
  NOTI_MAIL_FROM_ADDRESS: z.string().default('no-reply@shopsifu.live'),
  SEC_MAIL_FROM_ADDRESS: z.string().default('security@shopsifu.live'),

  // Admin
  ADMIN_NAME: z.string(),
  ADMIN_PASSWORD: z.string(),
  ADMIN_EMAIL: z.string(),
  ADMIN_PHONE_NUMBER: z.string(),
  SECRET_API_KEY: z.string(),

  // Session Durations
  SESSION_DEFAULT_DURATION_MS: z.coerce.number().int().positive().default(86400000), // 1 day
  SESSION_REMEMBER_ME_DURATION_MS: z.coerce.number().int().positive().default(2592000000) // 30 days
})

// Xác thực cấu hình
const configServer = configSchema.safeParse(process.env)
if (!configServer.success) {
  console.log('Các giá trị khai báo trong file .env không hợp lệ')
  console.error(configServer.error.format())
  process.exit(1)
}

const parsedConfig = configServer.data
const nodeEnv = parsedConfig.NODE_ENV

/**
 * Chuyển đổi chuỗi thời gian sang milliseconds
 */
const convertMs = (value: string, defaultValue: number): number => {
  try {
    const calculatedMs = ms(value)
    if (typeof calculatedMs === 'number' && !isNaN(calculatedMs)) {
      return calculatedMs
    }
    console.warn(`[Config] Invalid time string: '${value}'. Using default: ${defaultValue}ms.`)
    return defaultValue
  } catch (error) {
    console.warn(`[Config] Error parsing time: '${value}'. Using default: ${defaultValue}ms.`)
    return defaultValue
  }
}

const getCookieConfig = () => {
  return {
    ACCESS_TOKEN: {
      path: '/',
      domain: parsedConfig.COOKIE_DOMAIN,
      maxAge: convertMs(parsedConfig.ACCESS_TOKEN_EXPIRES_IN, ms('10m')),
      httpOnly: true,
      secure: true,
      sameSite: 'none'
    },
    REFRESH_TOKEN: {
      path: '/',
      domain: parsedConfig.COOKIE_DOMAIN,
      maxAge: convertMs(parsedConfig.REFRESH_TOKEN_EXPIRES_IN, ms('1d')),
      httpOnly: true,
      secure: true,
      sameSite: 'none'
    },
    SLT_TOKEN: {
      path: '/',
      domain: parsedConfig.COOKIE_DOMAIN,
      maxAge: convertMs(parsedConfig.SLT_JWT_EXPIRES_IN, ms('5m')),
      httpOnly: true,
      secure: true,
      sameSite: 'none'
    },
    OAUTH_NONCE: {
      path: '/',
      domain: parsedConfig.COOKIE_DOMAIN,
      maxAge: convertMs(parsedConfig.NONCE_COOKIE_MAX_AGE || '5m', ms('5m')),
      httpOnly: true,
      secure: true,
      sameSite: 'none' // Luôn đặt là 'none' để dễ test với Postman
    },
    OAUTH_PENDING_LINK: {
      path: '/',
      domain: parsedConfig.COOKIE_DOMAIN,
      maxAge: convertMs(parsedConfig.PENDING_LINK_TOKEN_EXPIRES_IN, ms('15m')),
      httpOnly: true,
      secure: true,
      sameSite: 'none'
    }
  }
}

// Cấu hình chung cho cookie
const { ACCESS_TOKEN, REFRESH_TOKEN, SLT_TOKEN, OAUTH_NONCE, OAUTH_PENDING_LINK } = getCookieConfig()

/**
 * Thiết lập cấu hình cookie
 */
const cookieConfig = {
  accessToken: ACCESS_TOKEN,
  refreshToken: REFRESH_TOKEN,
  sltToken: SLT_TOKEN,
  nonce: OAUTH_NONCE,
  csrfToken: {
    name: CookieNames.XSRF_TOKEN,
    path: parsedConfig.COOKIE_PATH_CSRF,
    domain: parsedConfig.COOKIE_DOMAIN,
    httpOnly: false, // JavaScript cần đọc được
    secure: true, // Trong development vẫn cần secure=true
    sameSite: 'none' // Trong development cần sameSite=none
  },
  csrfSecret: {
    name: '_csrf',
    path: parsedConfig.COOKIE_PATH_CSRF,
    domain: parsedConfig.COOKIE_DOMAIN,
    httpOnly: true,
    secure: true,
    sameSite: 'none',
    signed: true
  },
  oauthPendingLinkToken: OAUTH_PENDING_LINK
}

// Cấu hình chung đã chuyển đổi và tổng hợp
const envConfig = {
  ...parsedConfig,
  // Thời gian đã chuyển đổi sang milliseconds
  ACCESS_TOKEN_COOKIE_MAX_AGE: convertMs(parsedConfig.ACCESS_TOKEN_EXPIRES_IN, ms('10m')),
  REFRESH_TOKEN_COOKIE_MAX_AGE: convertMs(parsedConfig.REFRESH_TOKEN_EXPIRES_IN, ms('1d')),
  REMEMBER_ME_REFRESH_TOKEN_COOKIE_MAX_AGE: convertMs(parsedConfig.REMEMBER_ME_REFRESH_TOKEN_EXPIRES_IN, ms('14d')),
  ABSOLUTE_SESSION_LIFETIME_MS: convertMs(parsedConfig.ABSOLUTE_SESSION_LIFETIME, ms('30d')),

  // Cấu hình chung cho cookie
  cookieConfig: {
    secure: nodeEnv === 'production',
    sameSite: nodeEnv === 'production' ? 'none' : 'lax',
    domain: parsedConfig.COOKIE_DOMAIN
  },

  // Cấu hình chi tiết cho từng loại cookie
  cookie: cookieConfig
}

export default () => envConfig
