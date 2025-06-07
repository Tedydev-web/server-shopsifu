import { ThrottlerGuard } from '@nestjs/throttler'
import { Injectable } from '@nestjs/common'
import { Request } from 'express'

@Injectable()
export class ThrottlerProxyGuard extends ThrottlerGuard {
  protected getTracker(req: Request): Promise<string> {
    const ip = req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || req.ip
    if (typeof ip === 'string') {
      return Promise.resolve(ip)
    }
    if (Array.isArray(ip)) {
      return Promise.resolve(ip[0])
    }
    return super.getTracker(req)
  }
}
