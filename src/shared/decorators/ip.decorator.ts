import { createParamDecorator, ExecutionContext } from '@nestjs/common'
import { Request } from 'express'
import { extractRealIpFromRequest } from '../utils/http.utils'

/**
 * Extracts the real IP address of the client from the request.
 * It intelligently checks various headers to work behind reverse proxies like Nginx or Cloudflare.
 */
export const Ip = createParamDecorator((_: unknown, ctx: ExecutionContext): string => {
  const request = ctx.switchToHttp().getRequest<Request>()
  return extractRealIpFromRequest(request)
})
