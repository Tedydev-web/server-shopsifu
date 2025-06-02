import z from 'zod'
import fs from 'fs'
import path from 'path'
import { config } from 'dotenv'
import ms from 'ms'
import { CookieNames } from 'src/shared/constants/auth.constant'

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
  GOOGLE_CLIENT_REDIRECT_URI: z.string(),

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
  SECRET_API_KEY: z.string()
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

/**
 * Cấu hình cookie dựa trên môi trường
 *
 * Đặc biệt quan trọng cho 2FA flow:
 * - SLT cookie phải được cấu hình đúng để lưu trữ trạng thái 2FA setup
 * - CSRF token cần được xử lý đặc biệt trong môi trường development
 * - Cookie security (httpOnly, secure, sameSite) ảnh hưởng trực tiếp đến bảo mật
 */
const getCookieConfig = () => {
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
      // Trong môi trường development, CSRF token vẫn cần secure=true và sameSite=none cho cross-site
      // nhưng các cookie khác có thể giữ cấu hình ít hạn chế hơn
      cookieSecure = false
      cookieSameSite = 'lax'
      cookieDomain = undefined
      break
  }

  return { cookieSecure, cookieSameSite, cookieDomain }
}

// Cấu hình chung cho cookie
const { cookieSecure, cookieSameSite, cookieDomain } = getCookieConfig()

/**
 * Thiết lập cấu hình cookie
 */
const cookieConfig = {
  accessToken: {
    name: CookieNames.ACCESS_TOKEN,
    path: parsedConfig.COOKIE_PATH_ACCESS_TOKEN,
    domain: cookieDomain,
    maxAge: convertMs(parsedConfig.ACCESS_TOKEN_EXPIRES_IN, ms('10m')),
    httpOnly: true,
    secure: cookieSecure,
    sameSite: cookieSameSite
  },
  refreshToken: {
    name: CookieNames.REFRESH_TOKEN,
    path: parsedConfig.COOKIE_PATH_REFRESH_TOKEN,
    domain: cookieDomain,
    maxAge: convertMs(parsedConfig.REFRESH_TOKEN_EXPIRES_IN, ms('1d')),
    httpOnly: true,
    secure: cookieSecure,
    sameSite: cookieSameSite
  },
  sltToken: {
    name: CookieNames.SLT_TOKEN,
    path: '/',
    domain: cookieDomain,
    maxAge: convertMs(parsedConfig.SLT_JWT_EXPIRES_IN, ms('5m')),
    httpOnly: true,
    secure: cookieSecure,
    sameSite: cookieSameSite
  },
  nonce: {
    name: CookieNames.OAUTH_NONCE,
    path: '/',
    domain: cookieDomain,
    maxAge: convertMs(parsedConfig.NONCE_COOKIE_MAX_AGE || '5m', ms('5m')),
    httpOnly: true,
    secure: cookieSecure,
    sameSite: cookieSameSite
  },
  csrfToken: {
    name: CookieNames.XSRF_TOKEN,
    path: parsedConfig.COOKIE_PATH_CSRF,
    domain: cookieDomain,
    httpOnly: false, // JavaScript cần đọc được
    secure: nodeEnv === 'development' ? true : cookieSecure, // Trong development vẫn cần secure=true
    sameSite: nodeEnv === 'development' ? 'none' : cookieSameSite // Trong development cần sameSite=none
  },
  csrfSecret: {
    name: '_csrf',
    path: parsedConfig.COOKIE_PATH_CSRF,
    domain: cookieDomain,
    httpOnly: true,
    secure: cookieSecure,
    sameSite: cookieSameSite,
    signed: true
  },
  oauthPendingLinkToken: {
    name: CookieNames.OAUTH_PENDING_LINK,
    path: '/',
    domain: cookieDomain,
    maxAge: convertMs(parsedConfig.PENDING_LINK_TOKEN_EXPIRES_IN, ms('15m')),
    httpOnly: true,
    secure: cookieSecure,
    sameSite: cookieSameSite
  }
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
    secure: cookieSecure,
    sameSite: cookieSameSite,
    domain: cookieDomain
  },

  // Cấu hình chi tiết cho từng loại cookie
  cookie: cookieConfig
}

export default envConfig
