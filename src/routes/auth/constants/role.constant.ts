export const RoleName = {
  Admin: 'ADMIN',
  Client: 'CLIENT',
  Seller: 'SELLER'
} as const

export type RoleNameValue = (typeof RoleName)[keyof typeof RoleName]
