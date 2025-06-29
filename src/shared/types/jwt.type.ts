export interface AccessTokenPayloadCreate {
  userId: number
  sessionId: string
  roleId: number
  roleName: string
}

export interface AccessTokenPayload extends AccessTokenPayloadCreate {
  jti: string
  exp: number
  iat: number
}

export interface RefreshTokenPayloadCreate {
  userId: number
  sessionId: string
}

export interface RefreshTokenPayload extends RefreshTokenPayloadCreate {
  jti: string
  exp: number
  iat: number
}
