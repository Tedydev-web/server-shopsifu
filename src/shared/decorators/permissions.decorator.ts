import { applyDecorators, SetMetadata } from '@nestjs/common'

export const PERMISSIONS_KEY = 'permissions'
export const PERMISSIONS_OPTIONS_KEY = 'permissions_options'

export enum PermissionCondition {
  AND = 'AND',
  OR = 'OR'
}

export interface PermissionOptions {
  condition?: PermissionCondition
}

/**
 * Decorator để định nghĩa các permission string cần thiết cho một endpoint.
 *
 * Mặc định, user chỉ cần có MỘT trong các permission được liệt kê (OR).
 *
 * @param permissions - Danh sách các permission string yêu cầu (ví dụ: ['User:create', 'User:read']).
 * @param options - Tùy chọn cho việc kiểm tra permission.
 *   - `condition: PermissionCondition.AND` yêu cầu user phải có TẤT CẢ các permission.
 *   - `condition: PermissionCondition.OR` (mặc định) yêu cầu user chỉ cần có MỘT permission.
 */
export const RequirePermissions = (
  permissions: string[],
  options: PermissionOptions = { condition: PermissionCondition.OR }
) => {
  return applyDecorators(SetMetadata(PERMISSIONS_KEY, permissions), SetMetadata(PERMISSIONS_OPTIONS_KEY, options))
}
