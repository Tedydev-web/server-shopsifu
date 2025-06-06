import { createParamDecorator, ExecutionContext } from '@nestjs/common'
import { Request } from 'express'
import { REQUEST_USER_KEY } from 'src/routes/auth/shared/constants/auth.constants'
import { AccessTokenPayload } from 'src/routes/auth/shared/auth.types'

export const ActiveUser = createParamDecorator((field: keyof AccessTokenPayload | undefined, ctx: ExecutionContext) => {
  const request = ctx.switchToHttp().getRequest<Request>()
  const user = request['user'] as AccessTokenPayload

  return field ? user?.[field] : user
})
