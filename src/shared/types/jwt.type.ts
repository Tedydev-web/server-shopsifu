export interface AccessTokenPayloadCreate {
  userId: number
  deviceId: number
  roleId: number
  roleName: string
  sessionId: string
  jti: string
  isDeviceTrustedInSession: boolean
}

export interface AccessTokenPayload extends AccessTokenPayloadCreate {
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

// Định nghĩa cho Pending Link Token
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
