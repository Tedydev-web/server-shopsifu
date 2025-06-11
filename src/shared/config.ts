import z from 'zod'
import fs from 'fs'
import path from 'path'
import { config } from 'dotenv'
import ms from 'ms'
import { CookieNames } from 'src/routes/auth/auth.constants'

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
  COOKIE_DOMAIN: z.string().optional(),

  // Access & Refresh Token
  ACCESS_TOKEN_SECRET: z.string(),
  ACCESS_TOKEN_EXPIRES_IN: z.string().default('10m'),
  REFRESH_TOKEN_SECRET: z.string(),
  REFRESH_TOKEN_EXPIRES_IN: z.string().default('1d'),
  REMEMBER_ME_REFRESH_TOKEN_EXPIRES_IN: z.string().default('14d'),
  ABSOLUTE_SESSION_LIFETIME: z.string().default('30d'),

  // OTP & Verification
  OTP_EXPIRES_IN: z.string().default('5m'),
  OTP_MAX_ATTEMPTS: z.coerce.number().int().positive().default(5),
  OTP_EXPIRY_SECONDS: z.coerce.number().int().positive().default(300), // 5 minutes

  // SLT (State-Linking Token)
  SLT_JWT_SECRET: z.string(),
  SLT_JWT_EXPIRES_IN: z.string().default('5m'),

  // Auth - Pending link
  PENDING_LINK_TOKEN_SECRET: z.string(),
  PENDING_LINK_TOKEN_EXPIRES_IN: z.string().default('15m'),
  NONCE_COOKIE_MAX_AGE: z.string().optional(),

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
const isProduction = parsedConfig.NODE_ENV === 'production'
const isDevlopment = parsedConfig.NODE_ENV === 'development'

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

const getCookieOptions = (httpOnly: boolean) => {
  return {
    httpOnly,
    secure: true, // Luôn là true cho cả dev và prod
    domain: parsedConfig.COOKIE_DOMAIN,
    sameSite: isDevlopment ? 'none' : 'lax' // 'none' cho dev để dễ test, 'lax' cho prod để cho phép cross-site với navigation
  }
}

/**
 * Định nghĩa cấu hình chi tiết cho từng loại cookie.
 */
const cookieDefinitions = {
  accessToken: {
    name: CookieNames.ACCESS_TOKEN,
    options: {
      ...getCookieOptions(true), // httpOnly: true
      maxAge: convertMs(parsedConfig.ACCESS_TOKEN_EXPIRES_IN, ms('10m'))
    }
  },
  refreshToken: {
    name: CookieNames.REFRESH_TOKEN,
    options: {
      ...getCookieOptions(true), // httpOnly: true
      maxAge: convertMs(parsedConfig.REFRESH_TOKEN_EXPIRES_IN, ms('1d'))
    }
  },
  slt: {
    name: CookieNames.SLT_TOKEN,
    options: {
      ...getCookieOptions(true), // httpOnly: true
      maxAge: convertMs(parsedConfig.SLT_JWT_EXPIRES_IN, ms('5m'))
    }
  },
  oauthNonce: {
    name: CookieNames.OAUTH_NONCE,
    options: {
      ...getCookieOptions(true), // httpOnly: true
      maxAge: convertMs(parsedConfig.NONCE_COOKIE_MAX_AGE || '5m', ms('5m'))
    }
  },
  oauthPendingLink: {
    name: CookieNames.OAUTH_PENDING_LINK,
    options: {
      ...getCookieOptions(true), // httpOnly: true
      maxAge: convertMs(parsedConfig.PENDING_LINK_TOKEN_EXPIRES_IN, ms('15m'))
    }
  },
  csrfToken: {
    name: CookieNames.XSRF_TOKEN,
    options: {
      ...getCookieOptions(false), // httpOnly: false - Client cần đọc được để set header
      secure: true
    }
  },
  csrfSecret: {
    name: '_csrf',
    options: {
      ...getCookieOptions(true) // httpOnly: true
    }
  }
}

// Cấu hình chung đã chuyển đổi và tổng hợp
const envConfig = {
  ...parsedConfig,
  isDevlopment,

  // Thời gian đã chuyển đổi sang milliseconds
  timeInMs: {
    accessToken: convertMs(parsedConfig.ACCESS_TOKEN_EXPIRES_IN, ms('10m')),
    refreshToken: convertMs(parsedConfig.REFRESH_TOKEN_EXPIRES_IN, ms('1d')),
    rememberMeRefreshToken: convertMs(parsedConfig.REMEMBER_ME_REFRESH_TOKEN_EXPIRES_IN, ms('14d')),
    absoluteSession: convertMs(parsedConfig.ABSOLUTE_SESSION_LIFETIME, ms('30d')),
    slt: convertMs(parsedConfig.SLT_JWT_EXPIRES_IN, ms('5m')),
    otp: convertMs(parsedConfig.OTP_EXPIRES_IN, ms('5m'))
  },

  // Cấu hình chi tiết cho từng loại cookie
  cookie: cookieDefinitions
}

export default () => envConfig
