import { createZodDto } from 'nestjs-zod'
import { z } from 'zod'
import { BasePaginationQueryDTO } from 'src/shared/dtos/pagination.dto'

// ===================================================================================
//                                     SCHEMAS
// ===================================================================================

// --- Schemas for Get Sessions ---
const SessionItemSchema = z.object({
  id: z.string(),
  createdAt: z.date(),
  lastActive: z.date(),
  ip: z.string(), // Optimized from ipAddress
  location: z.string(),
  browser: z.string().optional(),
  browserVer: z.string().optional(), // Optimized from browserVersion
  os: z.string().optional(),
  osVer: z.string().optional(), // Optimized from osVersion
  type: z.string().optional(), // Optimized from deviceType
  app: z.string().optional(),
  active: z.boolean(), // Optimized from isActive
  inactiveDuration: z.string().nullable(),
  isCurrent: z.boolean() // Optimized from isCurrentSession
})

const DeviceSessionGroupSchema = z.object({
  deviceId: z.number(),
  name: z.string(), // Optimized from deviceName
  type: z.string().optional(), // Optimized from deviceType
  os: z.string().optional(),
  osVer: z.string().optional(), // Optimized from osVersion
  browser: z.string().optional(),
  browserVer: z.string().optional(), // Optimized from browserVersion
  trusted: z.boolean(), // Optimized from isDeviceTrusted
  trustExp: z.date().nullable(), // Optimized from deviceTrustExpiration
  lastActive: z.date(),
  location: z.string(),
  activeSessions: z.number(), // Optimized from activeSessionsCount
  totalSessions: z.number(), // Optimized from totalSessionsCount
  isCurrent: z.boolean(), // Optimized from isCurrentDevice
  status: z.enum(['active', 'inactive', 'expired']).optional(), // Device status
  riskLevel: z.enum(['low', 'medium', 'high']).optional(), // Security risk level
  daysSinceLastUse: z.number().optional(), // Days since last activity
  sessions: z.array(SessionItemSchema)
})

export const GetGroupedSessionsResponseSchema = z.object({
  devices: z.array(DeviceSessionGroupSchema),
  metadata: z.object({
    page: z.number(),
    limit: z.number(),
    totalItems: z.number(),
    totalPages: z.number()
  })
})

// --- Request DTOs ---
export class GetSessionsQueryDto extends BasePaginationQueryDTO {}

// --- Schemas for Revoke Sessions ---
export const RevokeSessionsBodySchema = z
  .object({
    // Target sessions to revoke (required at least one of sessionIds or deviceIds)
    sessionIds: z.array(z.string()).optional(),
    deviceIds: z.array(z.number()).optional(),

    // Safety controls (optional - system will auto-decide if not specified)
    excludeCurrentSession: z.boolean().optional() // Auto-exclude current session to prevent unexpected logout
  })
  .refine((data) => data.sessionIds?.length || data.deviceIds?.length, {
    message: 'Must specify at least one of sessionIds or deviceIds'
  })

export const RevokeAllSessionsBodySchema = z.object({
  // Safety controls (optional - system will auto-decide if not specified)
  excludeCurrentSession: z.boolean().optional(), // Auto-exclude current session to prevent unexpected logout
  untrustAllDevices: z.boolean().optional().default(true) // Untrust all devices for maximum security
})

// --- Minimal Response Schemas ---
export const MinimalResponseSchema = z.object({
  message: z.string()
})

export const VerificationRequiredResponseSchema = MinimalResponseSchema.extend({
  verificationType: z.enum(['OTP', '2FA'])
})

export const SuccessWithDataResponseSchema = MinimalResponseSchema.extend({
  data: z.record(z.any()).optional()
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
export class RevokeSessionsBodyDto extends createZodDto(RevokeSessionsBodySchema) {}
export class RevokeAllSessionsBodyDto extends createZodDto(RevokeAllSessionsBodySchema) {}
export class DeviceIdParamsDto extends createZodDto(DeviceIdParamsSchema) {}
export class UpdateDeviceNameBodyDto extends createZodDto(UpdateDeviceNameBodySchema) {}

// --- Response DTOs ---
export class MinimalResponseDto extends createZodDto(MinimalResponseSchema) {}
export class VerificationRequiredResponseDto extends createZodDto(VerificationRequiredResponseSchema) {}
export class SuccessWithDataResponseDto extends createZodDto(SuccessWithDataResponseSchema) {}
export class GetGroupedSessionsResponseDto extends createZodDto(GetGroupedSessionsResponseSchema) {}
export class RevokeResponseDto extends createZodDto(RevokeResponseSchema) {}
