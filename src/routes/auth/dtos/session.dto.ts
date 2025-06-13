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
  totalSessionsCount: z.number(), // Thêm tổng số sessions
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
export const RevokeSessionsBodySchema = z
  .object({
    // Target sessions to revoke (required at least one of sessionIds or deviceIds)
    sessionIds: z.array(z.string()).optional(),
    deviceIds: z.array(z.number()).optional(),

    // Safety controls (optional - system will auto-decide if not specified)
    excludeCurrentSession: z.boolean().optional(), // Auto-exclude current session to prevent unexpected logout
    forceLogout: z.boolean().optional() // Explicit confirmation required for logout actions
  })
  .refine((data) => data.sessionIds?.length || data.deviceIds?.length, {
    message: 'Must specify at least one of sessionIds or deviceIds'
  })

export const RevokeAllSessionsBodySchema = z.object({
  // Safety controls (optional - system will auto-decide if not specified)
  excludeCurrentSession: z.boolean().optional(), // Auto-exclude current session to prevent unexpected logout
  forceLogout: z.boolean().optional() // Explicit confirmation required for logout actions
})

// --- Schemas for Revoke Response ---
export const RevokeResponseSchema = z.object({
  revokedSessionsCount: z.number(),
  untrustedDevicesCount: z.number(),
  willCauseLogout: z.boolean(),
  warningMessage: z.string().optional(),
  requiresConfirmation: z.boolean().optional(),
  autoProtected: z.boolean().optional() // Indicates if sessions were auto-excluded for safety
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
export class RevokeResponseDto extends createZodDto(RevokeResponseSchema) {}
