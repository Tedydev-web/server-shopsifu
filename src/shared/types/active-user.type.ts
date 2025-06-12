import { UserWithProfileAndRole } from 'src/routes/user/user.repository'
import { Role, User } from '@prisma/client'

/**
 * Represents the data of the currently authenticated user.
 * This is a partial representation, containing only the essential information needed
 * for authorization and context, reducing the risk of exposing sensitive data.
 * It is attached to the request object by authentication guards.
 */
export type ActiveUserData = Partial<UserWithProfileAndRole> & {
  sessionId: string
  deviceId: number
  isDeviceTrustedInSession: boolean
}

export type ActiveUserType = UserWithProfileAndRole & {
  sessionId: string
}
