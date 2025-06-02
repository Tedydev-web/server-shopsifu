import { createParamDecorator, ExecutionContext } from '@nestjs/common'
import { Request } from 'express'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'

export const ActiveUser = createParamDecorator((data: string | undefined, context: ExecutionContext) => {
  const request = context.switchToHttp().getRequest<Request>()
  const user = request['user'] as AccessTokenPayload

  return data ? user?.[data] : user
})
