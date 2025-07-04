import { ExceptionFactory } from 'src/shared/error'

// --- Permission-specific Exceptions sử dụng ExceptionFactory ---
export const PermissionAlreadyExistsException = ExceptionFactory.alreadyExists('permission.error.ALREADY_EXISTS', 'path')
