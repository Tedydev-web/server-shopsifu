import { createParamDecorator, ExecutionContext } from '@nestjs/common'
import { Request } from 'express'
import { AccessTokenPayload } from 'src/routes/auth/auth.types'
import { REQUEST_USER_KEY } from 'src/routes/auth/auth.constants'

export const ActiveUser = createParamDecorator((field: keyof AccessTokenPayload | undefined, ctx: ExecutionContext) => {
  const request = ctx.switchToHttp().getRequest<Request>()
  const user = request[REQUEST_USER_KEY] as AccessTokenPayload

  return field ? user?.[field] : user
})
