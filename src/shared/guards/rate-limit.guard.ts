import { CanActivate, ExecutionContext, Injectable, HttpException, HttpStatus } from '@nestjs/common'
import { Reflector } from '@nestjs/core'
import { RATE_LIMIT_KEY, RateLimitOptions } from 'src/shared/decorators/rate-limit.decorator'
import { Request, Response } from 'express'

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
    const response = context.switchToHttp().getResponse<Response>()
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

      // Thêm headers
      response.header('X-RateLimit-Limit', `${limit}`)
      response.header('X-RateLimit-Remaining', `${limit - 1}`)
      response.header('X-RateLimit-Reset', `${Math.ceil((now + ttl * 1000) / 1000)}`)

      return true
    }

    // Kiểm tra xem khoảng thời gian giới hạn đã trôi qua chưa
    if (now - record.firstRequestTime > ttl * 1000) {
      // Reset lại nếu đã hết thời gian
      this.records.set(key, { count: 1, firstRequestTime: now })

      // Thêm headers
      response.header('X-RateLimit-Limit', `${limit}`)
      response.header('X-RateLimit-Remaining', `${limit - 1}`)
      response.header('X-RateLimit-Reset', `${Math.ceil((now + ttl * 1000) / 1000)}`)

      return true
    }

    // Kiểm tra số lần thử còn lại
    if (record.count >= limit) {
      const resetTime = Math.ceil((record.firstRequestTime + ttl * 1000) / 1000)
      const remainingTime = Math.ceil((record.firstRequestTime + ttl * 1000 - now) / 1000)

      // Thêm headers ngay cả khi vượt quá giới hạn
      response.header('X-RateLimit-Limit', `${limit}`)
      response.header('X-RateLimit-Remaining', '0')
      response.header('X-RateLimit-Reset', `${resetTime}`)

      throw new HttpException(
        {
          statusCode: HttpStatus.TOO_MANY_REQUESTS,
          message: 'Quá nhiều yêu cầu, vui lòng thử lại sau',
          errorCode: 'RATE_LIMIT_EXCEEDED',
          remainingTime: remainingTime // thời gian còn lại tính bằng giây
        },
        HttpStatus.TOO_MANY_REQUESTS
      )
    }

    // Tăng số lần thử
    record.count += 1
    this.records.set(key, record)

    // Thêm headers cho request thành công
    response.header('X-RateLimit-Limit', `${limit}`)
    response.header('X-RateLimit-Remaining', `${limit - record.count}`)
    response.header('X-RateLimit-Reset', `${Math.ceil((record.firstRequestTime + ttl * 1000) / 1000)}`)

    return true
  }
}
