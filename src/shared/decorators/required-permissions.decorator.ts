import { SetMetadata } from '@nestjs/common'

export interface RequiredPermission {
  action: string
  subject: string
}

export const PERMISSIONS_KEY = 'permissions'
export const RequiredPermissions = (...permissions: RequiredPermission[]) => SetMetadata(PERMISSIONS_KEY, permissions)
