/**
 * Enum cho các tên role trong hệ thống
 */
export enum RoleName {
  SUPER_ADMIN = 'SUPER_ADMIN',
  ADMIN = 'ADMIN',
  MANAGER = 'MANAGER',
  EDITOR = 'EDITOR',
  USER = 'USER',
  CUSTOMER = 'CUSTOMER',
  GUEST = 'GUEST',
  CLIENT = 'CLIENT',
  SELLER = 'SELLER'
}

/**
 * Type helper cho RoleName
 */
export type RoleNameType = keyof typeof RoleName

/**
 * Mô tả quyền mặc định cho mỗi role
 */
export const RolePermissions: Record<RoleName, string[]> = {
  [RoleName.SUPER_ADMIN]: ['*'], // Tất cả quyền
  [RoleName.ADMIN]: ['users:*', 'roles:*', 'products:*', 'orders:*'],
  [RoleName.MANAGER]: ['users:read', 'products:*', 'orders:*'],
  [RoleName.EDITOR]: ['products:*'],
  [RoleName.USER]: ['products:read', 'orders:create', 'orders:read'],
  [RoleName.CUSTOMER]: ['products:read', 'orders:create', 'orders:read'],
  [RoleName.GUEST]: ['products:read'],
  [RoleName.CLIENT]: ['products:read', 'orders:create', 'orders:read', 'profile:*'],
  [RoleName.SELLER]: ['products:*', 'orders:read', 'profile:*', 'store:*']
}

/**
 * Thứ tự ưu tiên của các role
 */
export const RolePriority: Record<RoleName, number> = {
  [RoleName.SUPER_ADMIN]: 100,
  [RoleName.ADMIN]: 90,
  [RoleName.MANAGER]: 80,
  [RoleName.EDITOR]: 70,
  [RoleName.USER]: 50,
  [RoleName.CUSTOMER]: 30,
  [RoleName.GUEST]: 10,
  [RoleName.CLIENT]: 40,
  [RoleName.SELLER]: 60
}
