import { Injectable } from '@nestjs/common'
import { PureAbility, AbilityBuilder } from '@casl/ability'
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

@Injectable()
export class CaslAbilityFactory {
  createForUser(user: UserWithRolesAndPermissions) {
    const { can, cannot, build } = new AbilityBuilder<AppAbility>(createPrismaAbility)

    if (user.role.name === 'Admin' || user.role.isSystemRole) {
      can(Action.Manage, 'all') // admin can do anything
    } else {
      // User can manage their own profile
      can(Action.Update, 'UserProfile', { userId: user.id })
      can(Action.Read, 'UserProfile', { userId: user.id })

      if (user.role.permissions) {
        user.role.permissions.forEach((p) => {
          // Here we need to be careful with the subject type
          const subject = p.subject as keyof AppModelTypes
          can(p.action as Action, subject)
        })
      }
    }

    return build()
  }
}
