import { ExceptionFactory } from 'src/shared/error'

// --- Role-specific Exceptions sử dụng ExceptionFactory ---
export const RoleAlreadyExistsException = ExceptionFactory.alreadyExists('role.error.ALREADY_EXISTS', 'name')

export const ProhibitedActionOnBaseRoleException = ExceptionFactory.prohibitedActionOnBaseRole()
