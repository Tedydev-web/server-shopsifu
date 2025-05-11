import { CanActivate, ExecutionContext, Injectable, HttpException, HttpStatus } from '@nestjs/common'
import { Reflector } from '@nestjs/core'
import { RATE_LIMIT_KEY, RateLimitOptions } from 'src/shared/decorators/rate-limit.decorator'
import { Request } from 'express'

interface RateLimitRecord {
  count: number
  firstRequestTime: number
}

@Injectable()
export class RateLimitGuard implements CanActivate {
  private readonly records = new Map<string, RateLimitRecord>()

  constructor(private reflector: Reflector) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const rateLimitOptions = this.reflector.get<RateLimitOptions>(RATE_LIMIT_KEY, context.getHandler())

    if (!rateLimitOptions) {
      return true // Không áp dụng rate limiting nếu không có options
    }

    const { ttl, limit } = rateLimitOptions
    const request = context.switchToHttp().getRequest<Request>()
    const ip = request.ip || '127.0.0.1'
    const userAgent = request.headers['user-agent'] || 'unknown'
    const email = request.body?.email || 'anonymous'

    // Tạo khóa duy nhất dựa trên IP, user-agent, và endpoint
    const key = `${ip}-${userAgent}-${email}-${request.path}`

    const now = Date.now()
    const record = this.records.get(key)

    if (!record) {
      // Lần đầu tiên gọi API
      this.records.set(key, { count: 1, firstRequestTime: now })
      return true
    }

    // Kiểm tra xem khoảng thời gian giới hạn đã trôi qua chưa
    if (now - record.firstRequestTime > ttl * 1000) {
      // Reset lại nếu đã hết thời gian
      this.records.set(key, { count: 1, firstRequestTime: now })
      return true
    }

    // Kiểm tra số lần thử còn lại
    if (record.count >= limit) {
      throw new HttpException(
        {
          statusCode: HttpStatus.TOO_MANY_REQUESTS,
          message: 'Quá nhiều yêu cầu, vui lòng thử lại sau',
          errorCode: 'RATE_LIMIT_EXCEEDED',
          remainingTime: Math.ceil((record.firstRequestTime + ttl * 1000 - now) / 1000) // thời gian còn lại tính bằng giây
        },
        HttpStatus.TOO_MANY_REQUESTS
      )
    }

    // Tăng số lần thử
    record.count += 1
    this.records.set(key, record)

    return true
  }
}
