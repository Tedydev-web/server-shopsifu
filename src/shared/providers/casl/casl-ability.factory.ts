import { Injectable, Logger } from '@nestjs/common'
import { PureAbility, AbilityBuilder, Subject } from '@casl/ability'
import { PrismaQuery, Subjects as PrismaSubjects, createPrismaAbility } from '@casl/prisma'
import {
  User,
  Role,
  Permission,
  Product,
  Category,
  Order,
  UserProfile,
  Device,
  Brand,
  Variant,
  SKU,
  CartItem,
  Review
} from '@prisma/client'
import { get } from 'lodash'

export enum Action {
  Manage = 'manage', // wildcard for any action
  Create = 'create',
  Read = 'read',
  Update = 'update',
  Delete = 'delete'
}

type AppModelTypes = {
  User: User
  Role: Role
  Permission: Permission
  Product: Product
  Category: Category
  Order: Order
  UserProfile: UserProfile
  Device: Device
  Brand: Brand
  Variant: Variant
  SKU: SKU
  CartItem: CartItem
  Review: Review
}

export type Subjects = PrismaSubjects<AppModelTypes> | 'all'

export type AppAbility = PureAbility<[Action, Subjects], PrismaQuery>

export type UserWithRolesAndPermissions = User & {
  role: Role & {
    permissions?: Permission[]
  }
}

function interpolate(template: object, context: object) {
  let str = JSON.stringify(template)
  str = str.replace(/\{\{\s*(\S+)\s*\}\}/g, (match, path) => {
    const value = get(context, path)
    if (value !== undefined) {
      return typeof value === 'string' ? `"${value}"` : value
    }
    return match // Return original if path not found
  })
  try {
    return JSON.parse(str)
  } catch (e) {
    Logger.error('Failed to parse interpolated conditions', e)
    return {}
  }
}

@Injectable()
export class CaslAbilityFactory {
  private readonly logger = new Logger(CaslAbilityFactory.name)

  createForUser(user: UserWithRolesAndPermissions) {
    const { can, build } = new AbilityBuilder<AppAbility>(createPrismaAbility)

    if (!user.role) {
      this.logger.warn(`User with id ${user.id} has no role assigned.`)
      return build()
    }

    if (user.role.isSuperAdmin) {
      can(Action.Manage, 'all')
      return build()
    }

    if (user.role.permissions) {
      for (const permission of user.role.permissions) {
        try {
          const subject = permission.subject as keyof AppModelTypes | 'all'

          if (
            permission.conditions &&
            typeof permission.conditions === 'object' &&
            !Array.isArray(permission.conditions)
          ) {
            const conditions = interpolate(permission.conditions, { user })
            can(permission.action as Action, subject, conditions)
          } else {
            can(permission.action as Action, subject)
          }
        } catch (error) {
          this.logger.error(`Failed to process permission: ${permission.id}`, error)
        }
      }
    }

    // Default permissions for any authenticated user should be defined in the database
    // and assigned to a default role. However, for backward compatibility or core rules,
    // you can still define some here.
    // Example:
    can(Action.Update, 'UserProfile', { userId: user.id })
    can(Action.Read, 'UserProfile', { userId: user.id })
    can(Action.Read, 'Device', { userId: user.id })

    return build()
  }
}
