import { z } from 'zod'

export const DeviceSchema = z.object({
  id: z.number().int(),
  userId: z.number().int(),
  // user: z.lazy(() => UserSchema) // Circular dependency, handle if needed for specific use cases
  name: z.string().nullable().optional(),
  fingerprint: z.string().nullable().optional(),
  userAgent: z.string(),
  ip: z.string(),
  lastActive: z.date(),
  createdAt: z.date(),
  isActive: z.boolean().default(true),
  isTrusted: z.boolean().default(false),
  trustExpiration: z.date().nullable().optional(),
  lastKnownIp: z.string().nullable().optional(),
  lastKnownCountry: z.string().nullable().optional(),
  lastKnownCity: z.string().nullable().optional(),
  lastNotificationSentAt: z.date().nullable().optional()
})

export type DeviceType = z.infer<typeof DeviceSchema>
