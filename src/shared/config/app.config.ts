import { CorsOptions } from '@nestjs/common/interfaces/external/cors-options.interface'
import { registerAs } from '@nestjs/config'
import { CookieOptions } from 'express'

import { APP_ENVIRONMENT } from 'src/shared/enums/app.enum'

export default registerAs('app', (): Record<string, any> => {
  const corsOrigins = process.env.APP_CORS_ORIGINS
    ? process.env.APP_CORS_ORIGINS.split(',').map((origin: string): string => origin.trim())
    : ['*']

  const corsConfig: CorsOptions = {
    origin: corsOrigins,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Accept', 'x-csrf-token', 'X-CSRF-Token'],
    credentials: true,
    exposedHeaders: ['Content-Range', 'X-Content-Range']
  }

  const cookieConfig: CookieOptions = {
    maxAge: process.env.COOKIE_MAX_AGE ? Number.parseInt(process.env.COOKIE_MAX_AGE) : 24 * 60 * 60 * 1000, // 24 giờ mặc định
    httpOnly: process.env.COOKIE_HTTP_ONLY ? process.env.COOKIE_HTTP_ONLY === 'true' : true,
    secure: process.env.COOKIE_SECURE ? process.env.COOKIE_SECURE === 'true' : process.env.NODE_ENV === 'production',
    sameSite: (process.env.COOKIE_SAME_SITE as CookieOptions['sameSite']) || 'strict',
    path: process.env.COOKIE_PATH || '/',
    domain: process.env.COOKIE_DOMAIN || 'localhost',
    priority: (process.env.COOKIE_PRIORITY as CookieOptions['priority']) || 'high',
    partitioned: process.env.COOKIE_PARTITIONED ? process.env.COOKIE_PARTITIONED === 'true' : true
  }

  return {
    env: process.env.NODE_ENV ?? APP_ENVIRONMENT.LOCAL,
    name: process.env.APP_NAME ?? 'shopsifu',

    versioning: {
      enable: process.env.HTTP_VERSIONING_ENABLE === 'true',
      prefix: 'v',
      version: process.env.HTTP_VERSION ?? '1'
    },

    throttle: {
      ttl: 60,
      limit: 10
    },

    http: {
      host: process.env.HTTP_HOST ?? 'localhost',
      port: process.env.HTTP_PORT ? Number.parseInt(process.env.HTTP_PORT) : 3000
    },

    cors: corsConfig,
    cookie: cookieConfig,
    sentry: {
      dsn: process.env.SENTRY_DSN,
      environment: process.env.NODE_ENV ?? APP_ENVIRONMENT.LOCAL
    },

    debug: process.env.APP_DEBUG === 'true',
    logLevel: process.env.APP_LOG_LEVEL ?? 'info'
  }
})
