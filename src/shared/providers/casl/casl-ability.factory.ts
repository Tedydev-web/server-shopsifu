import { Injectable } from '@nestjs/common'
import { AbilityBuilder, AbilityClass, ExtractSubjectType, InferSubjects, PureAbility } from '@casl/ability'
import sift from 'sift'
import { User } from 'src/routes/user/user.model'
import { Role } from 'src/routes/role/role.model'
import { Permission } from 'src/routes/permission/permission.model'
import { ActiveUserData } from 'src/shared/types/active-user.type'

/**
 * @description
 * Defines all possible actions a user can perform on a subject.
 * 'manage' is a special keyword in CASL that represents "any action".
 */
export enum Action {
  Manage = 'manage', // wildcard for any action
  Create = 'create',
  Read = 'read',
  Update = 'update',
  Delete = 'delete',

  // Special actions for granular control if needed
  ReadOwn = 'read:own',
  UpdateOwn = 'update:own',
  DeleteOwn = 'delete:own'
}

/**
 * @description
 * Defines all subjects (entities) that can be permissioned.
 * This enum is the single source of truth for subject names.
 */
export enum AppSubject {
  User = 'User',
  Role = 'Role',
  Permission = 'Permission',
  Profile = 'Profile',
  Session = 'Session',
  Device = 'Device',
  Password = 'Password',
  TwoFactor = 'TwoFactor',
  SocialAccount = 'SocialAccount',
  All = 'all' // Represents "any subject"
}

/**
 * @description
 * Defines all subjects (entities) that can have permissions.
 * 'all' is a special keyword in CASL that represents "any subject".
 */
export type Subjects = InferSubjects<typeof User | typeof Role | typeof Permission, true> | AppSubject

/**
 * @description
 * Defines the application's ability type using CASL's PureAbility.
 * This provides strong typing for actions and subjects.
 */
export type AppAbility = PureAbility<[Action, Subjects]>

/**
 * Utility function to safely access nested properties of an object.
 * @param obj The object to access.
 * @param path The path to the property (e.g., 'a.b.c').
 * @returns The value at the specified path, or undefined if not found.
 */
function getNestedValue(obj: any, path: string): any {
  return path.split('.').reduce((acc, part) => acc && acc[part], obj)
}

@Injectable()
export class CaslAbilityFactory {
  createForUser(user: ActiveUserData, permissions: Permission[]): AppAbility {
    const { can, cannot, build } = new AbilityBuilder<AppAbility>(PureAbility as AbilityClass<AppAbility>)

    // Grant manage all permission if user has the specific permission
    if (permissions.some((p) => (p.action as any) === Action.Manage && (p.subject as any) === AppSubject.All)) {
      can(Action.Manage, AppSubject.All)
    }

    // Iterate over user permissions and build abilities
    permissions.forEach((permission) => {
      // Map string actions from DB to Action enum
      const action = this.mapAction(permission.action)

      // A simple mapping from string subject to a type might be needed
      // for now, we'll treat them as strings which is also valid in CASL
      const subject = permission.subject

      if (permission.conditions) {
        const interpolatedConditions = this.interpolateConditions(permission.conditions, user)
        can(action, subject as any, interpolatedConditions)
      } else {
        can(action, subject as any)
      }
    })

    return build({
      detectSubjectType: (item) => item.constructor as ExtractSubjectType<Subjects>,
      conditionsMatcher: (conditions) => sift(conditions)
    })
  }

  /**
   * Interpolates template variables in permission conditions with user data.
   * @param conditions The conditions object from the permission.
   * @param user The active user data.
   * @returns A new conditions object with variables replaced by actual values.
   */
  private interpolateConditions(conditions: any, user: ActiveUserData): any {
    const interpolated = { ...conditions }
    for (const key in interpolated) {
      const value = interpolated[key]
      if (typeof value === 'string' && value.startsWith('user.')) {
        interpolated[key] = getNestedValue(user, value.substring(5))
      }
    }
    return interpolated
  }

  private mapAction(action: string): Action {
    // Direct mapping for custom actions
    switch (action) {
      case 'read:own':
        return Action.ReadOwn
      case 'update:own':
        return Action.UpdateOwn
      case 'delete:own':
        return Action.DeleteOwn
    }
    // General mapping for standard CRUD
    const actionKey = action.charAt(0).toUpperCase() + action.slice(1)
    if (actionKey in Action) {
      return Action[actionKey as keyof typeof Action]
    }
    // Fallback for actions like 'manage'
    return action as Action
  }
}
