import { z } from 'zod'

export const DeviceSchema = z.object({
  id: z.number().int(),
  userId: z.number().int(),
  name: z.string(),
  ip: z.string(),
  userAgent: z.string(),
  lastActive: z.coerce.date(),
  createdAt: z.coerce.date(),
  updatedAt: z.coerce.date(),
  fingerprint: z.string().nullable(),
  isTrusted: z.boolean(),
  trustExpiresAt: z.coerce.date().nullable(),
  lastNotificationSentAt: z.coerce.date().nullable(),
  isActive: z.boolean(),
  browser: z.string().nullable(),
  browserVersion: z.string().nullable(),
  os: z.string().nullable(),
  osVersion: z.string().nullable(),
  deviceType: z.string().nullable(),
  deviceVendor: z.string().nullable(),
  deviceModel: z.string().nullable(),
})

export type DeviceType = z.infer<typeof DeviceSchema>
