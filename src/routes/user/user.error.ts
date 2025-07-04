import { ExceptionFactory } from 'src/shared/error'

// --- User-specific Exceptions sử dụng ExceptionFactory ---
export const UserAlreadyExistsException = ExceptionFactory.alreadyExists('user.error.ALREADY_EXISTS', 'email')

export const CannotUpdateAdminUserException = ExceptionFactory.cannotUpdateAdminUser()

export const CannotDeleteAdminUserException = ExceptionFactory.cannotDeleteAdminUser()

// Chỉ Admin mới có thể đặt role là ADMIN
export const CannotSetAdminRoleToUserException = ExceptionFactory.cannotSetAdminRoleToUser()

export const RoleNotFoundException = ExceptionFactory.unprocessableEntity('user.error.ROLE_NOT_FOUND', 'roleId')

// Không thể xóa hoặc cập nhật chính bản thân mình
export const CannotUpdateOrDeleteYourselfException = ExceptionFactory.cannotUpdateOrDeleteYourself()
