import { SetMetadata, UseGuards, applyDecorators } from '@nestjs/common'
import { AuthType, AuthTypeType, ConditionGuardType } from '../../routes/auth/auth.constants'
import { AuthenticationGuard } from '../../routes/auth/guards/authentication.guard'

export const IS_PUBLIC_KEY = 'isPublic'
export const ROLES_KEY = 'roles'
export const AUTH_TYPE_KEY = 'authType'

export const Auth = (
  authTypes: AuthTypeType[] = [AuthType.JWT],
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  options?: { condition: ConditionGuardType }
) => {
  const authGuards = authTypes.map(() => AuthenticationGuard)
  return applyDecorators(SetMetadata(AUTH_TYPE_KEY, authTypes), UseGuards(...authGuards))
}

export const IsPublic = () => SetMetadata(IS_PUBLIC_KEY, true)
export const RolesAllowed = (...roles: string[]) => SetMetadata(ROLES_KEY, roles)
