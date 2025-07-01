import { z } from 'zod'
import ms from 'ms'
import { config } from 'dotenv'
import { CookieNames } from './constants/cookie.constant'

// Load environment variables
config({ path: '.env' })

// ==================== VALIDATION SCHEMAS ====================

const AppConfigSchema = z.object({
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  PORT: z.coerce.number().int().positive().min(1).max(65535).default(3000),
  APP_NAME: z.string().min(1).max(100).default('Shopsifu'),
  API_KEY: z.string().min(32).max(128),
  CLIENT_URL: z.string().url(),
  EMAIL_FROM: z.string().email().default('noreply@shopsifu.com'),
  LOG_LEVEL: z.enum(['error', 'warn', 'info', 'debug']).default('info'),
})

const SecurityConfigSchema = z.object({
  CSRF_SECRET_LENGTH: z.coerce.number().int().positive().min(16).max(64).default(32),
  CSRF_HEADER_NAME: z.string().min(1).max(50).default('x-csrf-token'),
  COOKIE_SECRET: z.string().min(32).max(128),
  RATE_LIMIT_WINDOW_MS: z.coerce
    .number()
    .int()
    .positive()
    .default(15 * 60 * 1000), // 15 minutes
  RATE_LIMIT_MAX_REQUESTS: z.coerce.number().int().positive().default(100),
})

const JWTConfigSchema = z.object({
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
})

const DatabaseConfigSchema = z.object({
  DATABASE_URL: z.string().url(),
  DATABASE_POOL_MIN: z.coerce.number().int().positive().default(2),
  DATABASE_POOL_MAX: z.coerce.number().int().positive().default(10),
  DATABASE_TIMEOUT: z.coerce.number().int().positive().default(30000),
})

const RedisConfigSchema = z.object({
  REDIS_HOST: z.string().default('localhost'),
  REDIS_PORT: z.coerce.number().int().positive().min(1).max(65535).default(6379),
  REDIS_PASSWORD: z.string().optional(),
  REDIS_DB: z.coerce.number().int().min(0).max(15).default(0),
  REDIS_TTL: z.coerce.number().int().positive().default(3600), // 1 hour
  REDIS_MAX_RETRIES: z.coerce.number().int().positive().default(3),
})

const EmailConfigSchema = z.object({
  RESEND_API_KEY: z.string().min(32).max(128),
  EMAIL_FROM_NAME: z.string().default('Shopsifu Team'),
  EMAIL_TEMPLATE_DIR: z.string().default('./emails'),
  EMAIL_RATE_LIMIT: z.coerce.number().int().positive().default(10), // emails per minute
})

const OAuthConfigSchema = z.object({
  GOOGLE_CLIENT_ID: z.string().min(20).max(200),
  GOOGLE_CLIENT_SECRET: z.string().min(20).max(200),
  GOOGLE_REDIRECT_URI: z.string().url(),
  GOOGLE_SCOPE: z.string().default('email profile'),
})

const MediaConfigSchema = z.object({
  UPLOAD_MAX_SIZE: z.coerce
    .number()
    .int()
    .positive()
    .default(10 * 1024 * 1024), // 10MB
  UPLOAD_ALLOWED_TYPES: z.string().default('image/jpeg,image/png,image/webp'),
  UPLOAD_DIR: z.string().default('./upload'),
  STATIC_URL_PREFIX: z.string().default('/media/static'),
  CDN_URL: z.string().url().optional(),
})

const S3ConfigSchema = z.object({
  S3_REGION: z.string().min(1).max(50),
  S3_ACCESS_KEY: z.string().min(20).max(100),
  S3_SECRET_KEY: z.string().min(20).max(100),
  S3_BUCKET_NAME: z.string().min(1).max(63),
  S3_ENDPOINT: z.string().url().optional(),
  S3_FORCE_PATH_STYLE: z.coerce.boolean().default(false),
})

const AdminConfigSchema = z.object({
  ADMIN_NAME: z.string().min(1).max(100),
  ADMIN_PASSWORD: z.string().min(8).max(128),
  ADMIN_EMAIL: z.string().email(),
  ADMIN_PHONE_NUMBER: z.string().regex(/^\+?[\d\s\-()]+$/),
})

const FeatureConfigSchema = z.object({
  ENABLE_2FA: z.coerce.boolean().default(true),
  ENABLE_SOCIAL_LOGIN: z.coerce.boolean().default(true),
  ENABLE_DEVICE_TRACKING: z.coerce.boolean().default(true),
  ENABLE_AUDIT_LOG: z.coerce.boolean().default(true),
  DEVICE_TRUST_EXPIRATION_DAYS: z.coerce.number().int().positive().default(30),
  SESSION_TIMEOUT_MINUTES: z.coerce.number().int().positive().default(30),
})

// ==================== ROOT SCHEMA ====================

const RootConfigSchema = z.object({
  ...AppConfigSchema.shape,
  ...SecurityConfigSchema.shape,
  ...JWTConfigSchema.shape,
  ...DatabaseConfigSchema.shape,
  ...RedisConfigSchema.shape,
  ...EmailConfigSchema.shape,
  ...OAuthConfigSchema.shape,
  ...MediaConfigSchema.shape,
  ...S3ConfigSchema.shape,
  ...AdminConfigSchema.shape,
  ...FeatureConfigSchema.shape,
})

// ==================== VALIDATION ====================

const validatedConfig = RootConfigSchema.parse(process.env)

// ==================== CONFIG OBJECT ====================

const isProd = validatedConfig.NODE_ENV === 'production'
const isDev = validatedConfig.NODE_ENV === 'development'
const isTest = validatedConfig.NODE_ENV === 'test'

const envConfig = {
  // Environment flags
  isProd,
  isDev,
  isTest,

  // App configuration
  app: {
    env: validatedConfig.NODE_ENV,
    port: validatedConfig.PORT,
    name: validatedConfig.APP_NAME,
    apiKey: validatedConfig.API_KEY,
    clientUrl: validatedConfig.CLIENT_URL,
    logLevel: validatedConfig.LOG_LEVEL,
  },

  // Security configuration
  security: {
    csrf: {
      secretLength: validatedConfig.CSRF_SECRET_LENGTH,
      headerName: validatedConfig.CSRF_HEADER_NAME,
    },
    rateLimit: {
      windowMs: validatedConfig.RATE_LIMIT_WINDOW_MS,
      maxRequests: validatedConfig.RATE_LIMIT_MAX_REQUESTS,
    },
  },

  // JWT configuration
  jwt: {
    accessToken: {
      secret: validatedConfig.ACCESS_TOKEN_SECRET,
      expiresIn: validatedConfig.ACCESS_TOKEN_EXPIRES_IN,
      expiresInMs: ms(validatedConfig.ACCESS_TOKEN_EXPIRES_IN),
    },
    refreshToken: {
      secret: validatedConfig.REFRESH_TOKEN_SECRET,
      expiresIn: validatedConfig.REFRESH_TOKEN_EXPIRES_IN,
      expiresInMs: ms(validatedConfig.REFRESH_TOKEN_EXPIRES_IN),
    },
    issuer: validatedConfig.JWT_ISSUER,
    audience: validatedConfig.JWT_AUDIENCE,
  },

  // Cookie configuration
  cookie: (() => {
    const getBaseOptions = (prefix: '' | '__Host-', httpOnly: boolean) => ({
      secure: isProd,
      sameSite: isProd ? ('strict' as const) : ('lax' as const),
      httpOnly,
      path: '/',
      ...(prefix === '__Host-' && { domain: undefined }),
    })

    return {
      secret: validatedConfig.COOKIE_SECRET,
      definitions: {
        accessToken: {
          name: CookieNames.ACCESS_TOKEN,
          prefix: '',
          options: {
            ...getBaseOptions('', true),
            maxAge: ms(validatedConfig.ACCESS_TOKEN_EXPIRES_IN),
          },
        },
        refreshToken: {
          name: CookieNames.REFRESH_TOKEN,
          prefix: isProd ? '__Host-' : '',
          options: {
            ...getBaseOptions(isProd ? '__Host-' : '', true),
            maxAge: ms(validatedConfig.REFRESH_TOKEN_EXPIRES_IN),
          },
        },
        csrfSecret: {
          name: CookieNames.CSRF_SECRET,
          prefix: isProd ? '__Host-' : '',
          options: getBaseOptions(isProd ? '__Host-' : '', true),
        },
        csrfToken: {
          name: CookieNames.CSRF_TOKEN,
          prefix: '',
          options: {
            ...getBaseOptions('', false),
          },
        },
        slt: {
          name: CookieNames.SLT,
          prefix: isProd ? '__Host-' : '',
          options: {
            ...getBaseOptions(isProd ? '__Host-' : '', true),
            maxAge: ms('15m'),
          },
        },
      },
    }
  })(),

  // Database configuration
  database: {
    url: validatedConfig.DATABASE_URL,
    pool: {
      min: validatedConfig.DATABASE_POOL_MIN,
      max: validatedConfig.DATABASE_POOL_MAX,
    },
    timeout: validatedConfig.DATABASE_TIMEOUT,
  },

  // Redis configuration
  redis: {
    host: validatedConfig.REDIS_HOST,
    port: validatedConfig.REDIS_PORT,
    password: validatedConfig.REDIS_PASSWORD,
    db: validatedConfig.REDIS_DB,
    ttl: validatedConfig.REDIS_TTL,
    maxRetries: validatedConfig.REDIS_MAX_RETRIES,
  },

  // Email configuration
  email: {
    from: validatedConfig.EMAIL_FROM,
    fromName: validatedConfig.EMAIL_FROM_NAME,
    apiKey: validatedConfig.RESEND_API_KEY,
    templateDir: validatedConfig.EMAIL_TEMPLATE_DIR,
    rateLimit: validatedConfig.EMAIL_RATE_LIMIT,
  },

  // OAuth configuration
  oauth: {
    google: {
      clientId: validatedConfig.GOOGLE_CLIENT_ID,
      clientSecret: validatedConfig.GOOGLE_CLIENT_SECRET,
      redirectUri: validatedConfig.GOOGLE_REDIRECT_URI,
      scope: validatedConfig.GOOGLE_SCOPE,
    },
  },

  // Media configuration
  media: {
    upload: {
      maxSize: validatedConfig.UPLOAD_MAX_SIZE,
      allowedTypes: validatedConfig.UPLOAD_ALLOWED_TYPES.split(','),
      directory: validatedConfig.UPLOAD_DIR,
    },
    static: {
      urlPrefix: validatedConfig.STATIC_URL_PREFIX,
      cdnUrl: validatedConfig.CDN_URL,
    },
  },

  // S3 configuration
  s3: {
    region: validatedConfig.S3_REGION,
    accessKey: validatedConfig.S3_ACCESS_KEY,
    secretKey: validatedConfig.S3_SECRET_KEY,
    bucketName: validatedConfig.S3_BUCKET_NAME,
    endpoint: validatedConfig.S3_ENDPOINT,
    forcePathStyle: validatedConfig.S3_FORCE_PATH_STYLE,
  },

  // Admin configuration
  admin: {
    name: validatedConfig.ADMIN_NAME,
    password: validatedConfig.ADMIN_PASSWORD,
    email: validatedConfig.ADMIN_EMAIL,
    phoneNumber: validatedConfig.ADMIN_PHONE_NUMBER,
  },

  // Feature flags
  features: {
    enable2FA: validatedConfig.ENABLE_2FA,
    enableSocialLogin: validatedConfig.ENABLE_SOCIAL_LOGIN,
    enableDeviceTracking: validatedConfig.ENABLE_DEVICE_TRACKING,
    enableAuditLog: validatedConfig.ENABLE_AUDIT_LOG,
    deviceTrustExpirationDays: validatedConfig.DEVICE_TRUST_EXPIRATION_DAYS,
    sessionTimeoutMinutes: validatedConfig.SESSION_TIMEOUT_MINUTES,
  },

  // Timeouts and durations (in milliseconds)
  timeouts: {
    accessToken: ms(validatedConfig.ACCESS_TOKEN_EXPIRES_IN),
    refreshToken: ms(validatedConfig.REFRESH_TOKEN_EXPIRES_IN),
    otp: ms('5m'),
    rememberMe: ms('30d'),
    session: ms(`${validatedConfig.SESSION_TIMEOUT_MINUTES}m`),
  },
}

// ==================== EXPORTS ====================

export default () => envConfig
export type EnvConfigType = typeof envConfig
