import { createParamDecorator, ExecutionContext } from '@nestjs/common'
import { Request } from 'express'

export const Ip = createParamDecorator((_: unknown, ctx: ExecutionContext): string => {
  const request = ctx.switchToHttp().getRequest<Request>()

  // Try multiple methods to get the real IP address
  const candidates = [
    request.headers['cf-connecting-ip'], // Cloudflare
    request.headers['x-real-ip'], // Nginx
    request.headers['x-forwarded-for'], // Standard proxy header
    request.headers['x-client-ip'], // Apache
    request.headers['x-cluster-client-ip'], // Cluster
    request.headers['forwarded-for'],
    request.headers['forwarded'],
    request.connection?.remoteAddress,
    request.socket?.remoteAddress,
    request.ip
  ].filter(Boolean)

  for (const candidate of candidates) {
    if (typeof candidate === 'string') {
      // Handle comma-separated IPs (take the first one)
      const ip = candidate.split(',')[0].trim()
      if (ip) {
        return ip
      }
    }
  }

  // Fallback to localhost if no IP is detected
  return '127.0.0.1'
})
