import { Action } from 'src/shared/providers/casl/casl-ability.factory'
import { CheckAbilities } from 'src/shared/providers/casl/casl.policies'

export const CanCreatePermissionPolicy = CheckAbilities({
  action: Action.Create,
  subject: 'Permission'
})

export const CanReadPermissionPolicy = CheckAbilities({
  action: Action.Read,
  subject: 'Permission'
})

export const CanUpdatePermissionPolicy = CheckAbilities({
  action: Action.Update,
  subject: 'Permission'
})

export const CanDeletePermissionPolicy = CheckAbilities({
  action: Action.Delete,
  subject: 'Permission'
})
