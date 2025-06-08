import { createParamDecorator, ExecutionContext } from '@nestjs/common'
import { Request } from 'express'
import { AccessTokenPayload } from 'src/shared/types/auth.types'

export const ActiveUser = createParamDecorator((field: keyof AccessTokenPayload | undefined, ctx: ExecutionContext) => {
  const request = ctx.switchToHttp().getRequest<Request>()
  const user = request['user'] as AccessTokenPayload

  return field ? user?.[field] : user
})
