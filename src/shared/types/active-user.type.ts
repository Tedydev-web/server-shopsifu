import { UserWithProfileAndRole } from 'src/routes/user/user.repository'

/**
 * Represents the data of the currently authenticated user.
 * It combines the full user entity from the database (including role and permissions)
 * with session-specific data extracted from the JWT (sessionId, deviceId).
 * This provides a single, consistent object for use in guards, controllers, and services.
 */
export type ActiveUserData = UserWithProfileAndRole & {
  sessionId: string
  deviceId: number
  isDeviceTrustedInSession: boolean
}
