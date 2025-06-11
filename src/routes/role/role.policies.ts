import { Action } from 'src/shared/providers/casl/casl-ability.factory'
import { CheckAbilities } from 'src/shared/providers/casl/casl.policies'

export const CanCreateRolePolicy = CheckAbilities({
  action: Action.Create,
  subject: 'Role'
})

export const CanReadRolePolicy = CheckAbilities({
  action: Action.Read,
  subject: 'Role'
})

export const CanUpdateRolePolicy = CheckAbilities({
  action: Action.Update,
  subject: 'Role'
})

export const CanDeleteRolePolicy = CheckAbilities({
  action: Action.Delete,
  subject: 'Role'
})
