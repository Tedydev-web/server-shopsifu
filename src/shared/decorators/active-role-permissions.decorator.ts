import { createParamDecorator, ExecutionContext } from '@nestjs/common'
import { REQUEST_ROLE_PERMISSIONS } from 'src/shared/constants/auth.constant'
import { RolePermissionsType } from 'src/shared/models/shared-role.model'

export const ActiveRolePermissions = createParamDecorator(
  (field: keyof RolePermissionsType | undefined, context: ExecutionContext) => {
    const request = context.switchToHttp().getRequest()
    const rolePermissions: RolePermissionsType | undefined = request[REQUEST_ROLE_PERMISSIONS]
    return field ? rolePermissions?.[field] : rolePermissions
  },
)
