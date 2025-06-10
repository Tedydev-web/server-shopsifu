import { Injectable } from '@nestjs/common'
import { subject } from '@casl/ability'

import { IPolicyHandler } from 'src/shared/casl/casl.types'
import { AppAbility, Action } from 'src/shared/casl/casl-ability.factory'
import { ProfileRepository } from './profile.repository'
import { UserWithProfileAndRole } from 'src/routes/user/user.repository'
import { REQUEST_USER_KEY } from '../auth/auth.constants'
import { AccessTokenPayload } from 'src/routes/auth/auth.types'

@Injectable()
export class UpdateProfilePolicyHandler implements IPolicyHandler {
  constructor(private readonly profileRepository: ProfileRepository) {}

  async handle(ability: AppAbility, request: any): Promise<boolean> {
    const activeUser: UserWithProfileAndRole & AccessTokenPayload = request[REQUEST_USER_KEY]
    if (!activeUser) {
      return false
    }

    const userProfile = await this.profileRepository.findByUserId(activeUser.userId)
    if (!userProfile) {
      return false
    }

    return ability.can(Action.Update, subject('UserProfile', userProfile))
  }
}
