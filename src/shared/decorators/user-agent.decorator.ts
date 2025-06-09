import { createParamDecorator, ExecutionContext } from '@nestjs/common'
import { Request } from 'express'
import { HttpHeader } from 'src/shared/constants/http.constants'

export const UserAgent = createParamDecorator((_: unknown, ctx: ExecutionContext): string | undefined => {
  const request = ctx.switchToHttp().getRequest<Request>()
  const userAgentValue = request.headers[HttpHeader.USER_AGENT]

  if (Array.isArray(userAgentValue)) {
    // It's uncommon for User-Agent to be an array, but headers can be.
    // Return the first element if it's an array, or undefined if empty.
    return userAgentValue.length > 0 ? userAgentValue[0] : undefined
  }
  return userAgentValue // This will be string or undefined
})
