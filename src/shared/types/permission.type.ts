import { User, Role, UserProfile } from '@prisma/client'
import { AppSubject } from '../providers/casl/casl-ability.factory'
import { ActiveUserData } from './active-user.type'

/**
 * Defines a template variable that can be used in permission conditions.
 * These variables will be interpolated at runtime with the active user's data.
 * Example: 'user.id', 'user.organizationId'
 */
export type StringKeyOf<T> = Extract<keyof T, string>
export type ConditionTemplateVariable = `user.${StringKeyOf<ActiveUserData>}`

/**
 * Represents a condition object for a specific subject.
 * The keys are the fields of the resource, and the values can be static values
 * or a template variable that will be interpolated.
 */
export type SubjectConditions<T> = {
  [P in keyof T]?: T[P] | ConditionTemplateVariable
}

/**
 * A mapped type that defines the specific condition structure for each AppSubject.
 * This provides type-safety and autocompletion when defining permissions.
 */
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
