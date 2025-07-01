import { z } from 'zod'
import ms from 'ms'
import { config } from 'dotenv'
import { CookieNames } from './constants/cookie.constant'

// Tải biến môi trường từ file .env
config({ path: '.env' })

// --- Zod Schemas for Validation ---
const AppConfigSchema = z.object({
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  PORT: z.coerce.number().int().positive().default(3000),
  APP_NAME: z.string().default('Shopsifu'),
  API_KEY: z.string(),
  CLIENT_URL: z.string().url(),
  EMAIL_FROM: z.string().email().default('noreply@shopsifu.com'),
})

const CsrfConfigSchema = z.object({
  CSRF_SECRET_LENGTH: z.coerce.number().int().positive().default(32),
  CSRF_HEADER_NAME: z.string().default('x-csrf-token'),
})

const JWTConfigSchema = z.object({
  ACCESS_TOKEN_SECRET: z.string(),
  ACCESS_TOKEN_EXPIRES_IN: z.string().default('15m'),
  REFRESH_TOKEN_SECRET: z.string(),
  REFRESH_TOKEN_EXPIRES_IN: z.string().default('7d'),
})

const CookieConfigSchema = z.object({
  COOKIE_SECRET: z.string(),
})

const DatabaseConfigSchema = z.object({
  DATABASE_URL: z.string(),
})

const GoogleConfigSchema = z.object({
  GOOGLE_CLIENT_ID: z.string(),
  GOOGLE_CLIENT_SECRET: z.string(),
  GOOGLE_REDIRECT_URI: z.string().url(),
})

const OTPConfigSchema = z.object({
  OTP_EXPIRES_IN: z.string().default('5m'),
})

const AdminConfigSchema = z.object({
  ADMIN_NAME: z.string(),
  ADMIN_PASSWORD: z.string(),
  ADMIN_EMAIL: z.string().email(),
  ADMIN_PHONE_NUMBER: z.string(),
})

const ResendConfigSchema = z.object({
  RESEND_API_KEY: z.string(),
})

const RedisConfigSchema = z.object({
  REDIS_HOST: z.string().default('localhost'),
  REDIS_PORT: z.coerce.number().int().positive().default(6379),
  REDIS_PASSWORD: z.string().optional(),
  REDIS_DB: z.coerce.number().int().default(0),
})

const DeviceConfigSchema = z.object({
  DEVICE_TRUST_EXPIRATION_DAYS: z.coerce.number().int().positive().default(30),
})

const MediaConfigSchema = z.object({
  PREFIX_STATIC_ENPOINT: z.string().default('http://localhost:3000/media/static'),
})

// --- Root Schema ---
const RootConfigSchema = AppConfigSchema.merge(JWTConfigSchema)
  .merge(CookieConfigSchema)
  .merge(DatabaseConfigSchema)
  .merge(GoogleConfigSchema)
  .merge(OTPConfigSchema)
  .merge(AdminConfigSchema)
  .merge(ResendConfigSchema)
  .merge(CsrfConfigSchema)
  .merge(RedisConfigSchema)
  .merge(DeviceConfigSchema)
  .merge(MediaConfigSchema)

// --- Validation and Parsing ---
const validatedConfig = RootConfigSchema.parse(process.env)

// --- Structured and Typed Config Object ---
const isProd = validatedConfig.NODE_ENV === 'production'

const envConfig = {
  isProd,
  app: {
    env: validatedConfig.NODE_ENV,
    port: validatedConfig.PORT,
    name: validatedConfig.APP_NAME,
    apiKey: validatedConfig.API_KEY,
    clientUrl: validatedConfig.CLIENT_URL,
    emailFrom: validatedConfig.EMAIL_FROM,
  },
  csrf: {
    secretLength: validatedConfig.CSRF_SECRET_LENGTH,
    headerName: validatedConfig.CSRF_HEADER_NAME,
  },
  jwt: {
    accessToken: {
      secret: validatedConfig.ACCESS_TOKEN_SECRET,
      expiresIn: validatedConfig.ACCESS_TOKEN_EXPIRES_IN,
    },
    refreshToken: {
      secret: validatedConfig.REFRESH_TOKEN_SECRET,
      expiresIn: validatedConfig.REFRESH_TOKEN_EXPIRES_IN,
    },
  },
  cookie: (() => {
    const getBaseOptions = (prefix: '' | '__Host-', httpOnly: boolean) => {
      const base = {
        secure: true,
        sameSite: 'lax' as const,
        httpOnly,
      }
      if (prefix === '__Host-') {
        return { ...base, path: '/', domain: undefined }
      }
      return { ...base, path: '/' }
    }

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
          options: getBaseOptions(isProd ? '__Host-' : '', true),
        },
        csrfSecret: {
          name: CookieNames.CSRF_SECRET,
          prefix: isProd ? '__Host-' : '',
          options: {
            ...getBaseOptions(isProd ? '__Host-' : '', true),
            // Session cookie, no maxAge
          },
        },
        csrfToken: {
          name: CookieNames.CSRF_TOKEN,
          prefix: '',
          options: {
            ...getBaseOptions('', false), // Client-side script needs to read this
            // Session cookie, no maxAge
          },
        },
        slt: {
          name: CookieNames.SLT,
          prefix: isProd ? '__Host-' : '',
          options: {
            ...getBaseOptions(isProd ? '__Host-' : '', true),
            maxAge: ms('15m'), // State-Linking Token should have a short lifespan
          },
        },
      },
    }
  })(),
  timeInMs: {
    accessToken: ms(validatedConfig.ACCESS_TOKEN_EXPIRES_IN),
    refreshToken: ms(validatedConfig.REFRESH_TOKEN_EXPIRES_IN),
    otp: ms(validatedConfig.OTP_EXPIRES_IN),
    rememberMe: ms('30d'),
  },
  database: {
    url: validatedConfig.DATABASE_URL,
  },
  google: {
    clientId: validatedConfig.GOOGLE_CLIENT_ID,
    clientSecret: validatedConfig.GOOGLE_CLIENT_SECRET,
    redirectUri: validatedConfig.GOOGLE_REDIRECT_URI,
  },
  otp: {
    expiresIn: validatedConfig.OTP_EXPIRES_IN,
  },
  resend: {
    apiKey: validatedConfig.RESEND_API_KEY,
  },
  redis: {
    host: validatedConfig.REDIS_HOST,
    port: validatedConfig.REDIS_PORT,
    password: validatedConfig.REDIS_PASSWORD,
    db: validatedConfig.REDIS_DB,
  },
  device: {
    trustExpirationDays: validatedConfig.DEVICE_TRUST_EXPIRATION_DAYS,
  },
  admin: {
    name: validatedConfig.ADMIN_NAME,
    password: validatedConfig.ADMIN_PASSWORD,
    email: validatedConfig.ADMIN_EMAIL,
    phoneNumber: validatedConfig.ADMIN_PHONE_NUMBER,
  },
  media: {
    prefixStaticEnpoint: validatedConfig.PREFIX_STATIC_ENPOINT,
  },
}

// --- Export for NestJS ConfigModule ---
export default () => envConfig
export type EnvConfigType = typeof envConfig
