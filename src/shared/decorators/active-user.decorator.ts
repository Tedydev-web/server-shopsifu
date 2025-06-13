import { createParamDecorator, ExecutionContext } from '@nestjs/common'
import { ClsServiceManager } from 'nestjs-cls'
import { AccessTokenPayload } from 'src/routes/auth/auth.types'
import { REQUEST_USER_KEY } from 'src/routes/auth/auth.constants'

export const ActiveUser = createParamDecorator((field: keyof AccessTokenPayload | undefined, ctx: ExecutionContext) => {
  const cls = ClsServiceManager.getClsService()
  const user = cls.get<AccessTokenPayload>(REQUEST_USER_KEY)
  if (!user) {
    return null
  }

  return field ? user?.[field] : user
})
