import { z } from 'zod'
import fs from 'fs'
import path from 'path'
import { config } from 'dotenv'
import ms from 'ms'
// import { CookieOptions } from 'express' // For SameSite type // Removed as CookieOptions is not strictly needed with explicit types

config({
  path: '.env'
})

if (!fs.existsSync(path.resolve('.env'))) {
  console.log('Không tìm thấy file .env')
  process.exit(1)
}

// Zod schema for environment variables
const EnvSchema = z.object({
  // App
  NODE_ENV: z.enum(['development', 'production', 'test', 'staging']).default('development'),
  PORT: z.coerce.number().int().positive().default(3000),
  API_HOST_URL: z.string().url().default('http://localhost:3000'),
  API_LOCAL_URL: z.string().url().default('http://localhost:3000'),
  FRONTEND_HOST_URL: z.string().url().default('http://localhost:3001'),
  FRONTEND_LOCAL_URL: z.string().url().default('http://localhost:3001'),
  APP_NAME: z.string().default('Shopsifu'),

  // Database
  DATABASE_URL: z.string().url(),

  // JWT & Cookies
  ACCESS_TOKEN_SECRET: z.string().min(32),
  REFRESH_TOKEN_SECRET: z.string().min(32),
  VERIFICATION_JWT_SECRET: z.string().min(32).default('default_verification_jwt_secret_32_chars'),
  SLT_JWT_SECRET: z.string().min(32).default('default_slt_jwt_secret_must_be_32_chars_long'),
  ACCESS_TOKEN_EXPIRY: z.string().default('15m'),
  REFRESH_TOKEN_EXPIRY: z.string().default('7d'),
  VERIFICATION_JWT_EXPIRES_IN: z.string().default('10m'),
  REMEMBER_ME_REFRESH_TOKEN_EXPIRY: z.string().default('30d'),
  SLT_JWT_EXPIRES_IN: z.string().default('5m'),
  SLT_EXPIRY_SECONDS: z.coerce.number().int().positive().default(300),
  ABSOLUTE_SESSION_LIFETIME_MS: z.preprocess(
    (val) => {
      if (val === undefined || val === null || val === '') {
        return undefined
      }
      const num = Number(val)
      if (Number.isInteger(num) && num > 0) {
        return num
      }
      return undefined
    },
    z
      .number()
      .int()
      .positive()
      .default(30 * 24 * 60 * 60 * 1000)
  ),
  COOKIE_SECRET: z.string().min(32),
  COOKIE_DOMAIN: z.string().optional(),

  // CSRF
  CSRF_SECRET: z.string().min(32),

  // Google OAuth
  GOOGLE_CLIENT_ID: z.string(),
  GOOGLE_CLIENT_SECRET: z.string(),
  GOOGLE_SERVER_REDIRECT_URI: z.string().url(),
  GOOGLE_CLIENT_REDIRECT_URI: z.string().url(),

  // Email (Resend)
  RESEND_API_KEY: z.string(),
  EMAIL_FROM_ADDRESS: z.string().email(),

  // Redis
  REDIS_HOST: z.string().default('localhost'),
  REDIS_PORT: z.coerce.number().int().positive().default(6379),
  REDIS_PASSWORD: z.string().optional(),
  REDIS_DB: z.coerce.number().int().min(0).default(0),

  // Rate Limiting
  THROTTLE_TTL: z.coerce.number().int().positive().default(60),
  THROTTLE_LIMIT: z.coerce.number().int().positive().default(20),

  // Cache
  CACHE_TTL: z.coerce
    .number()
    .int()
    .positive()
    .default(5 * 60),

  // Geolocation
  GEOIP_LITE_COUNTRY_DB_PATH: z.string().optional(),
  GEOIP_LITE_CITY_DB_PATH: z.string().optional(),

  // Admin
  ADMIN_EMAIL: z.string().email().default('admin@shopsifu.com'),
  ADMIN_DEFAULT_PASSWORD: z.string().min(6).default('Admin@123'),
  ADMIN_NAME: z.string().default('Shopsifu Admin'),
  ADMIN_DEFAULT_PHONE_NUMBER: z.string().default('0000000000'),

  // Logging
  LOG_LEVEL: z.enum(['log', 'error', 'warn', 'debug', 'verbose']).default('debug'),

  // Other
  OTP_EXPIRES_IN: z.string().default('10m'),
  OTP_EXPIRY_SECONDS: z.coerce.number().int().positive().default(300),
  OTP_MAX_ATTEMPTS: z.coerce.number().int().positive().default(5),

  MAX_SESSIONS_PER_USER: z.coerce.number().int().positive().default(10),
  MAX_DEVICES_PER_USER: z.coerce.number().int().positive().default(5),
  SESSION_INACTIVITY_TIMEOUT_MS: z.coerce.number().int().positive().default(ms('30m')),
  SECRET_API_KEY: z.string().optional(),
  FEATURE_FLAG_ENABLE_DETAILED_ERROR_LOGGING: z
    .preprocess((val) => String(val).toLowerCase() === 'true', z.boolean())
    .default(true),
  REDIS_KEY_PREFIX: z.string().optional().default('shopsifu:'),
  REDIS_DEFAULT_TTL_MS: z.coerce
    .number()
    .int()
    .positive()
    .default(5 * 60 * 1000)
})

export type EnvConfigType = z.infer<typeof EnvSchema>

// Type for cookie configurations within envConfig
interface CommonCookieOptionsType {
  httpOnly: boolean
  secure: boolean
  path: string
  sameSite: 'strict' | 'lax'
  domain?: string
}

interface FullCookieOptionsType extends CommonCookieOptionsType {
  name: string
  maxAge: number // in milliseconds
}

interface CsrfTokenCookieOptionsType {
  // Specifically for the XSRF-TOKEN cookie
  name: string
  httpOnly: boolean // Should be false for XSRF-TOKEN
  secure: boolean
  path: string
  sameSite: 'strict' | 'lax'
  domain?: string
  // maxAge is not typically set for XSRF-TOKEN cookie by csurf, it's session-based or managed by the csrfSecretCookie
}

let envConfigSingleton: EnvConfigType & {
  cookie: {
    accessToken: FullCookieOptionsType
    refreshToken: FullCookieOptionsType
    sltToken: FullCookieOptionsType
    csrfToken: CsrfTokenCookieOptionsType
    csrfSecretCookie: FullCookieOptionsType
    REMEMBER_ME_REFRESH_TOKEN_COOKIE_MAX_AGE: number
    REFRESH_TOKEN_COOKIE_MAX_AGE: number
  }
}

function createEnvConfig(env: Record<string, string | undefined>) {
  const validatedEnv = EnvSchema.parse(env)

  const nodeEnv = validatedEnv.NODE_ENV
  const cookieSecure = nodeEnv === 'production' || nodeEnv === 'staging'
  const cookieDomain = validatedEnv.COOKIE_DOMAIN || undefined

  const commonBaseCookieOptions: Omit<CommonCookieOptionsType, 'domain' | 'sameSite'> = {
    httpOnly: true,
    secure: cookieSecure,
    path: '/'
  }

  const accessTokenMaxAge = ms(validatedEnv.ACCESS_TOKEN_EXPIRY)
  const refreshTokenMaxAge = ms(validatedEnv.REFRESH_TOKEN_EXPIRY)
  const sltTokenMaxAge = ms(validatedEnv.SLT_JWT_EXPIRES_IN)
  const rememberMeRefreshTokenMaxAge = ms(validatedEnv.REMEMBER_ME_REFRESH_TOKEN_EXPIRY)

  const accessTokenCookie: FullCookieOptionsType = {
    name: 'access_token',
    ...commonBaseCookieOptions,
    sameSite: 'lax' as const,
    maxAge: accessTokenMaxAge,
    domain: cookieDomain
  }

  const refreshTokenCookie: FullCookieOptionsType = {
    name: 'refresh_token',
    ...commonBaseCookieOptions,
    sameSite: 'strict' as const,
    maxAge: refreshTokenMaxAge,
    domain: cookieDomain
  }

  const sltTokenCookie: FullCookieOptionsType = {
    name: 'slt_token',
    ...commonBaseCookieOptions,
    sameSite: 'strict' as const,
    maxAge: sltTokenMaxAge,
    domain: cookieDomain
  }

  const csrfTokenCookie: CsrfTokenCookieOptionsType = {
    name: 'xsrf-token',
    httpOnly: false,
    secure: cookieSecure,
    path: '/',
    sameSite: 'strict' as const,
    domain: cookieDomain
  }

  const csrfSecretCookie: FullCookieOptionsType = {
    name: '_csrf',
    ...commonBaseCookieOptions,
    sameSite: 'strict' as const,
    maxAge: ms('1y'),
    domain: cookieDomain
  }

  return {
    ...validatedEnv,
    cookie: {
      accessToken: accessTokenCookie,
      refreshToken: refreshTokenCookie,
      sltToken: sltTokenCookie,
      csrfToken: csrfTokenCookie,
      csrfSecretCookie: csrfSecretCookie,
      REMEMBER_ME_REFRESH_TOKEN_COOKIE_MAX_AGE: rememberMeRefreshTokenMaxAge,
      REFRESH_TOKEN_COOKIE_MAX_AGE: refreshTokenMaxAge
    }
  }
}

try {
  envConfigSingleton = createEnvConfig(process.env)
} catch (error) {
  if (error instanceof z.ZodError) {
    console.error('Environment variable validation error:', error.issues)
    process.exit(1)
  }
  console.error('Unknown error during environment variable validation:', error)
  process.exit(1)
}

export default envConfigSingleton
