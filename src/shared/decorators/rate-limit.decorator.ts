import { SetMetadata } from '@nestjs/common'

export const RATE_LIMIT_KEY = 'rate_limit'

export interface RateLimitOptions {
  ttl: number // thời gian tính bằng giây
  limit: number // số lần thử tối đa
}

export const RateLimit = (options: RateLimitOptions) => SetMetadata(RATE_LIMIT_KEY, options)
