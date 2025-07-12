import {
	ForbiddenException,
	UnprocessableEntityException
} from '@nestjs/common'

export const UserAlreadyExistsException = new UnprocessableEntityException([
	{
		message: 'user.error.ALREADY_EXISTS',
		path: 'email'
	}
])

export const CannotUpdateAdminUserException = new ForbiddenException(
	'user.error.CANNOT_UPDATE_ADMIN_USER'
)

export const CannotDeleteAdminUserException = new ForbiddenException(
	'user.error.CANNOT_DELETE_ADMIN_USER'
)

// Chỉ Admin mới có thể đặt role là ADMIN
export const CannotSetAdminRoleToUserException = new ForbiddenException(
	'user.error.CANNOT_SET_ADMIN_ROLE_TO_USER'
)

export const RoleNotFoundException = new UnprocessableEntityException([
	{
		message: 'user.error.ROLE_NOT_FOUND',
		path: 'roleId'
	}
])

// Không thể xóa hoặc cập nhật chính bản thân mình
export const CannotUpdateOrDeleteYourselfException = new ForbiddenException(
	'user.error.CANNOT_UPDATE_OR_DELETE_YOURSELF'
)
