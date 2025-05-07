import { createParamDecorator, ExecutionContext } from '@nestjs/common'
import requestIp from 'request-ip'
export const IP = createParamDecorator((data: unknown, ctx: ExecutionContext): string => {
  const request = ctx.switchToHttp().getRequest()
  const clientIp = requestIp.getClientIp(request)
  return String(clientIp)
})
