import { User, Role, UserProfile } from '@prisma/client'
import { AppSubject } from '../providers/casl/casl-ability.factory'
import { ActiveUserData } from './active-user.type'

export type StringKeyOf<T> = Extract<keyof T, string>
export type ConditionTemplateVariable = `user.${StringKeyOf<ActiveUserData>}`

export type SubjectConditions<T> = {
  [P in keyof T]?: T[P] | ConditionTemplateVariable
}

export type PermissionConditions = {
  [AppSubject.User]?: SubjectConditions<User>
  [AppSubject.Role]?: SubjectConditions<Role>
  [AppSubject.Profile]?: SubjectConditions<UserProfile>
  // Add other subjects here as they get conditional permissions
}

export interface PermissionDefinition {
  subject: string
  action: string
  description?: string
  isSystemPermission?: boolean
  conditions?: Record<string, any>
}
