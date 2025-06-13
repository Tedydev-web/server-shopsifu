import { UserWithProfileAndRole } from 'src/routes/user/user.repository'

export type ActiveUserData = Partial<UserWithProfileAndRole> & {
  sessionId: string
  deviceId: number
  isDeviceTrustedInSession: boolean
}

export type ActiveUserType = UserWithProfileAndRole & {
  sessionId: string
}
