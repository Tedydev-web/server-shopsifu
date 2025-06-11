import { Action } from 'src/shared/providers/casl/casl-ability.factory'
import { CheckAbilities } from 'src/shared/providers/casl/casl.policies'

export const CanCreateUserPolicy = CheckAbilities({
  action: Action.Create,
  subject: 'User'
})

export const CanReadUserPolicy = CheckAbilities({
  action: Action.Read,
  subject: 'User'
})

export const CanUpdateUserPolicy = CheckAbilities({
  action: Action.Update,
  subject: 'User'
})

export const CanDeleteUserPolicy = CheckAbilities({
  action: Action.Delete,
  subject: 'User'
})
