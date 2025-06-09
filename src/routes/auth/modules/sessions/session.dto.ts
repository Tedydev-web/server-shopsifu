import { createZodDto } from 'nestjs-zod'
import { z } from 'zod'
import { VerificationNeededResponseSchema } from '../../services/auth-verification.dto'

// ===================================================================================
// Lược đồ cho nội dung yêu cầu
// ===================================================================================

// --- Get Sessions ---
export const GetSessionsQuerySchema = z.object({
  page: z.coerce.number().min(1).default(1),
  limit: z.coerce.number().min(1).max(100).default(5)
})

// --- Revoke Sessions ---
export const RevokeSessionsBodySchema = z
  .object({
    sessionIds: z.array(z.string()).optional(),
    deviceIds: z.array(z.number()).optional(),
    excludeCurrentSession: z.boolean().default(true)
  })
  .refine(({ sessionIds, deviceIds }) => !!sessionIds?.length || !!deviceIds?.length, {
    message: 'Bạn phải chỉ định ít nhất một trong các tùy chọn: sessionIds hoặc deviceIds'
  })

export const RevokeAllSessionsBodySchema = z.object({
  excludeCurrentSession: z.boolean().default(true)
})

// --- Update Device ---
export const DeviceIdParamsSchema = z.object({
  deviceId: z.coerce.number()
})

export const UpdateDeviceNameBodySchema = z.object({
  name: z.string().min(1).max(100)
})

// ===================================================================================
// Lược đồ cho dữ liệu phản hồi (sẽ được bao bọc bởi TransformInterceptor)
// ===================================================================================

// --- Get Sessions ---
const SessionItemSchema = z.object({
  id: z.string(),
  createdAt: z.date(),
  lastActive: z.date(),
  ipAddress: z.string(),
  location: z.string().nullable().optional(),
  browser: z.string().nullable().optional(),
  browserVersion: z.string().nullable().optional(),
  app: z.string().nullable().optional(),
  isActive: z.boolean(),
  inactiveDuration: z.string().nullable().optional(),
  isCurrentSession: z.boolean()
})

const DeviceSessionGroupSchema = z.object({
  deviceId: z.number(),
  deviceName: z.string().nullable(),
  deviceType: z.string().nullable().optional(),
  os: z.string().nullable().optional(),
  osVersion: z.string().nullable().optional(),
  browser: z.string().nullable().optional(),
  browserVersion: z.string().nullable().optional(),
  isDeviceTrusted: z.boolean(),
  deviceTrustExpiration: z.date().nullable().optional(),
  lastActive: z.date().nullable().optional(),
  location: z.string().nullable().optional(),
  activeSessionsCount: z.number().optional(),
  isCurrentDevice: z.boolean(),
  sessions: z.array(SessionItemSchema)
})

export const GetGroupedSessionsResponseSchema = z.object({
  data: z.array(DeviceSessionGroupSchema),
  meta: z.object({
    currentPage: z.number(),
    itemsPerPage: z.number(),
    totalItems: z.number(),
    totalPages: z.number()
  })
})

// --- Revoke Sessions ---
export const RevokeSessionsResponseSchema = z.object({
  revokedSessionsCount: z.number(),
  untrustedDevicesCount: z.number()
})

// --- Update Device Name ---
export const UpdateDeviceNameResponseSchema = z.object({
  deviceId: z.number(),
  name: z.string()
})

// ===================================================================================
// DTO Classes
// ===================================================================================

// --- Request DTOs ---
export class GetSessionsQueryDto extends createZodDto(GetSessionsQuerySchema) {}
export class RevokeSessionsBodyDto extends createZodDto(RevokeSessionsBodySchema) {}
export class RevokeAllSessionsBodyDto extends createZodDto(RevokeAllSessionsBodySchema) {}
export class DeviceIdParamsDto extends createZodDto(DeviceIdParamsSchema) {}
export class UpdateDeviceNameBodyDto extends createZodDto(UpdateDeviceNameBodySchema) {}

// --- Response DTOs ---
export class GetGroupedSessionsResponseDto extends createZodDto(GetGroupedSessionsResponseSchema) {}
export class RevokeSessionsResponseDto extends createZodDto(RevokeSessionsResponseSchema) {}
export class VerificationNeededResponseDto extends createZodDto(VerificationNeededResponseSchema) {}
export class UpdateDeviceNameResponseDto extends createZodDto(UpdateDeviceNameResponseSchema) {}
