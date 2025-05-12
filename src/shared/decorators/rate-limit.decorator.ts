import { SetMetadata } from '@nestjs/common'

export const RATE_LIMIT_KEY = 'rate-limit'

export interface RateLimitOptions {
  limit: number
  ttl: number
}

export const RateLimit = (options: RateLimitOptions) => SetMetadata(RATE_LIMIT_KEY, options)
