/**
 * Định nghĩa payload của Access Token khi tạo mới
 */
export interface AccessTokenPayloadCreate {
  userId: number
  deviceId?: number
  roleId?: number
  roleName?: string
  sessionId?: string
  jti: string
  isDeviceTrustedInSession?: boolean
  email?: string
  type?: 'ACCESS' | 'REFRESH'
  exp?: number
  iat?: number
}

/**
 * Định nghĩa payload của Access Token khi đã được verify
 */
export interface AccessTokenPayload extends Omit<AccessTokenPayloadCreate, 'exp' | 'iat'> {
  deviceId: number
  roleId: number
  roleName: string
  sessionId: string
  isDeviceTrustedInSession: boolean
  exp: number
  iat: number
}

// Removed RefreshTokenPayloadCreate and RefreshTokenPayload as Refresh Tokens are UUIDs, not JWTs
// export interface RefreshTokenPayloadCreate {
//   userId: number
// }

// export interface RefreshTokenPayload extends RefreshTokenPayloadCreate {
//   exp: number
//   iat: number
// }

/**
 * Định nghĩa cho Pending Link Token
 */
export interface PendingLinkTokenPayloadCreate {
  existingUserId: number
  googleId: string
  googleEmail: string
  googleName?: string | null
  googleAvatar?: string | null
}

export interface PendingLinkTokenPayload extends PendingLinkTokenPayloadCreate {
  jti: string
  exp: number
  iat: number
}
