import { SetMetadata } from '@nestjs/common'
import { RoleName } from '../constants/role.constant'

export const ROLES_KEY = 'roles'
export const Roles = (...roles: (keyof typeof RoleName)[]) =>
  SetMetadata(
    ROLES_KEY,
    roles.map((roleKey) => RoleName[roleKey])
  )
