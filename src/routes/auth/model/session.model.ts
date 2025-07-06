import { z } from 'zod'

export const SessionSchema = z.object({
  id: z.string().uuid(),
  userId: z.number().int(),
  deviceId: z.number().int(),
  ipAddress: z.string(),
  userAgent: z.string(),
  lastActiveAt: z.date(),
  revokedAt: z.date().nullable(),
  expiresAt: z.date(),
  createdAt: z.date(),
  updatedAt: z.date()
})

export type SessionType = z.infer<typeof SessionSchema>
