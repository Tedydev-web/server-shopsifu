import { createZodDto } from 'nestjs-zod'
import { z } from 'zod'

// ===================================================================================
//                                     SCHEMAS
// ===================================================================================

// --- Schemas for Get Sessions ---
const SessionItemSchema = z.object({
  id: z.string(),
  createdAt: z.date(),
  lastActive: z.date(),
  ipAddress: z.string(),
  location: z.string(),
  browser: z.string().optional(),
  browserVersion: z.string().optional(),
  os: z.string().optional(),
  osVersion: z.string().optional(),
  deviceType: z.string().optional(),
  app: z.string().optional(),
  isActive: z.boolean(),
  inactiveDuration: z.string().nullable(),
  isCurrentSession: z.boolean()
})

const DeviceSessionGroupSchema = z.object({
  deviceId: z.number(),
  deviceName: z.string(),
  deviceType: z.string().optional(),
  os: z.string().optional(),
  osVersion: z.string().optional(),
  browser: z.string().optional(),
  browserVersion: z.string().optional(),
  isDeviceTrusted: z.boolean(),
  deviceTrustExpiration: z.date().nullable(),
  lastActive: z.date(),
  location: z.string(),
  activeSessionsCount: z.number(),
  isCurrentDevice: z.boolean(),
  sessions: z.array(SessionItemSchema)
})

export const GetGroupedSessionsResponseSchema = z.object({
  devices: z.array(DeviceSessionGroupSchema),
  meta: z.object({
    currentPage: z.number(),
    itemsPerPage: z.number(),
    totalItems: z.number(),
    totalPages: z.number()
  })
})

export const GetSessionsQuerySchema = z.object({
  page: z.coerce.number().int().positive().optional().default(1),
  limit: z.coerce.number().int().positive().optional().default(5)
})

// --- Schemas for Revoke Sessions ---
export const RevokeSessionsBodySchema = z.object({
  sessionIds: z.array(z.string()).optional(),
  deviceIds: z.array(z.number()).optional(),
  excludeCurrentSession: z.boolean().optional().default(false)
})

export const RevokeAllSessionsBodySchema = z.object({
  excludeCurrentSession: z.boolean().optional().default(true)
})

// --- Schemas for Update Device ---
export const DeviceIdParamsSchema = z.object({
  deviceId: z.coerce.number().int().positive()
})

export const UpdateDeviceNameBodySchema = z.object({
  name: z.string().min(1).max(50)
})

// ===================================================================================
//                                       DTOs
// ===================================================================================

// --- Request DTOs ---
export class GetSessionsQueryDto extends createZodDto(GetSessionsQuerySchema) {}
export class RevokeSessionsBodyDto extends createZodDto(RevokeSessionsBodySchema) {}
export class RevokeAllSessionsBodyDto extends createZodDto(RevokeAllSessionsBodySchema) {}
export class DeviceIdParamsDto extends createZodDto(DeviceIdParamsSchema) {}
export class UpdateDeviceNameBodyDto extends createZodDto(UpdateDeviceNameBodySchema) {}

// --- Response DTOs ---
export class GetGroupedSessionsResponseDto extends createZodDto(GetGroupedSessionsResponseSchema) {}
