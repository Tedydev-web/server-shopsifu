import { ForbiddenException, UnprocessableEntityException } from '@nestjs/common'

export const RoleAlreadyExistsException = new UnprocessableEntityException([
  {
    message: 'Error.RoleAlreadyExists',
    path: 'name',
  },
])

export const ProhibitedActionOnBaseRoleException = new ForbiddenException('Error.ProhibitedActionOnBaseRole')
