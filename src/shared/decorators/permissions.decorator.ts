import { SetMetadata } from '@nestjs/common'
import { Action, Subjects } from 'src/shared/providers/casl/casl-ability.factory'
import { Type } from '@nestjs/common'

export const PERMISSIONS_KEY = 'permissions'

export interface RequiredPermission {
  action: Action

  subject: Type<any> | Extract<Subjects, string>
}

export const RequirePermissions = (...permissions: RequiredPermission[]) => SetMetadata(PERMISSIONS_KEY, permissions)
