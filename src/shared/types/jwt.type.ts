export interface AccessTokenPayloadCreate {
  userId: number
  deviceId: number
  roleId: number
  roleName: string
}

export interface AccessTokenPayload extends AccessTokenPayloadCreate {
  exp: number
  iat: number
}

export interface RefreshTokenPayloadCreate {
  userId: number
}

export interface RefreshTokenPayload extends RefreshTokenPayloadCreate {
  exp: number
  iat: number
}

export interface EmailVerificationTokenPayload {
  email: string
  expiresAt: number
  type: string
}

export interface EmailVerificationTokenResult extends EmailVerificationTokenPayload {
  exp: number
  iat: number
}
