import { createZodDto } from 'nestjs-zod'
import { z } from 'zod'

// Get Sessions DTOs
export const GetSessionsQuerySchema = z.object({
  page: z.coerce.number().min(1).default(1),
  limit: z.coerce.number().min(1).max(100).default(10)
})

export const SessionResponseSchema = z.object({
  id: z.string(),
  deviceId: z.number(),
  createdAt: z.date(),
  lastActive: z.date(),
  ipAddress: z.string(),
  userAgent: z.string(),
  device: z
    .object({
      id: z.number(),
      name: z.string().nullable(),
      isTrusted: z.boolean()
    })
    .nullable()
    .optional()
})

export const GetSessionsResponseSchema = z.object({
  data: z.array(SessionResponseSchema),
  meta: z.object({
    page: z.number(),
    limit: z.number(),
    total: z.number(),
    totalPages: z.number()
  })
})

// Revoke Session DTOs
export const RevokeSessionParamsSchema = z.object({
  sessionId: z.string()
})

export const RevokeSessionResponseSchema = z.object({
  message: z.string()
})

// Revoke Multiple Sessions DTOs
export const RevokeSessionsBodySchema = z.object({
  sessionIds: z.array(z.string()),
  revokeAll: z.boolean().optional(),
  excludeCurrentSession: z.boolean().optional()
})

export const RevokeSessionsResponseSchema = z.object({
  message: z.string(),
  revokedCount: z.number()
})

// Update Device DTOs
export const DeviceIdParamsSchema = z.object({
  deviceId: z.string()
})

export const UpdateDeviceNameBodySchema = z.object({
  name: z.string().min(1).max(100)
})

export const UpdateDeviceNameResponseSchema = z.object({
  message: z.string()
})

// Trust/Untrust Device DTOs
export const TrustDeviceBodySchema = z.object({})

export const TrustDeviceResponseSchema = z.object({
  message: z.string()
})

export const UntrustDeviceBodySchema = z.object({})

export const UntrustDeviceResponseSchema = z.object({
  message: z.string()
})

// Create DTO classes
export class GetSessionsQueryDto extends createZodDto(GetSessionsQuerySchema) {}
export class SessionResponseDto extends createZodDto(SessionResponseSchema) {}
export class GetSessionsResponseDto extends createZodDto(GetSessionsResponseSchema) {}
export class RevokeSessionParamsDto extends createZodDto(RevokeSessionParamsSchema) {}
export class RevokeSessionResponseDto extends createZodDto(RevokeSessionResponseSchema) {}
export class RevokeSessionsBodyDto extends createZodDto(RevokeSessionsBodySchema) {}
export class RevokeSessionsResponseDto extends createZodDto(RevokeSessionsResponseSchema) {}
export class DeviceIdParamsDto extends createZodDto(DeviceIdParamsSchema) {}
export class UpdateDeviceNameBodyDto extends createZodDto(UpdateDeviceNameBodySchema) {}
export class UpdateDeviceNameResponseDto extends createZodDto(UpdateDeviceNameResponseSchema) {}
export class TrustDeviceBodyDto extends createZodDto(TrustDeviceBodySchema) {}
export class TrustDeviceResponseDto extends createZodDto(TrustDeviceResponseSchema) {}
export class UntrustDeviceBodyDto extends createZodDto(UntrustDeviceBodySchema) {}
export class UntrustDeviceResponseDto extends createZodDto(UntrustDeviceResponseSchema) {}
