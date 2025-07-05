import { ForbiddenException, UnprocessableEntityException } from '@nestjs/common'

export const RoleAlreadyExistsException = new UnprocessableEntityException([
  {
    message: 'role.error.ALREADY_EXISTS',
    path: 'name',
  },
])

export const ProhibitedActionOnBaseRoleException = new ForbiddenException('role.error.PROHIBITED_ACTION_ON_BASE_ROLE')
