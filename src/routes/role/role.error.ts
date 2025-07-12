import {
	ForbiddenException,
	UnprocessableEntityException
} from '@nestjs/common'

export const RoleAlreadyExistsException = new UnprocessableEntityException([
	{
		message: 'role.role.error.ALREADY_EXISTS',
		path: 'name'
	}
])

export const ProhibitedActionOnBaseRoleException = new ForbiddenException(
	'role.role.error.PROHIBITED_ACTION_ON_BASE_ROLE'
)
