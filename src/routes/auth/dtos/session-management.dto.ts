import { z } from 'zod'
import { createZodDto } from 'nestjs-zod'
import { EmptyBodySchema } from 'src/shared/models/request.model'
import { createPaginatedResponseSchema } from 'src/shared/models/pagination.model'

// Combined and consistent Device Schema
const BaseDeviceSchema = z.object({
  id: z.number().int(),
  name: z.string().nullable().describe('User-assigned name for the device'),
  type: z.enum(['desktop', 'mobile', 'tablet', 'wearable', 'tv', 'console', 'unknown']),
  os: z.string().nullable().describe('Operating System'),
  browser: z.string().nullable().describe('Browser name')
})

// Schema for device information within an active session
const ActiveSessionDeviceSchema = BaseDeviceSchema.extend({
  isCurrentDevice: z.boolean().describe('Is this the device making the current request?')
})

export const ActiveSessionSchema = z.object({
  sessionId: z.string().uuid(),
  device: ActiveSessionDeviceSchema, // Ensures this uses the correct, more limited schema
  ipAddress: z.string().nullable(),
  location: z.string().nullable().describe('Approximate location, e.g., City, Country'),
  loggedInAt: z.string(),
  lastActiveAt: z.string(),
  isCurrentSession: z.boolean().describe('Is this the session of the current request?')
})

// Sử dụng schema phân trang chuẩn cho active sessions response
export const GetActiveSessionsResSchema = createPaginatedResponseSchema(ActiveSessionSchema)

// ========== DTOs for Active Sessions ==========
export class GetActiveSessionsResDTO extends createZodDto(GetActiveSessionsResSchema) {}

// ========== Schemas for Revoking Session ==========
export const RevokeSessionParamsSchema = z.object({
  sessionId: z.string().uuid().describe('The UUID of the session to revoke')
})

// ========== DTOs for Revoking Session ==========
export class RevokeSessionParamsDTO extends createZodDto(RevokeSessionParamsSchema) {}

// ========== Schemas for Device Management (Managed Devices) ==========
export const DeviceInfoSchema = BaseDeviceSchema.extend({
  // Fields specific to managed device listing
  ip: z.string().optional().nullable(),
  location: z.string().optional().nullable(),
  createdAt: z.string().optional(),
  lastActive: z.string().optional(),
  isTrusted: z.boolean(),
  isCurrentDevice: z.boolean().optional() // Could be useful to highlight current device in a list of managed devices
})

// Sử dụng schema phân trang chuẩn cho managed devices response
export const GetDevicesResSchema = createPaginatedResponseSchema(DeviceInfoSchema)

// ========== DTOs for Device Management ==========
export class GetDevicesResDTO extends createZodDto(GetDevicesResSchema) {}

export const DeviceIdParamsSchema = z.object({
  deviceId: z.coerce.number().int().positive()
})

export const UpdateDeviceNameBodySchema = z.object({
  name: z.string().min(1).max(255).trim()
})

// ========== DTOs for Device Management ==========
export class DeviceIdParamsDTO extends createZodDto(DeviceIdParamsSchema) {}
export class UpdateDeviceNameBodyDTO extends createZodDto(UpdateDeviceNameBodySchema) {}
export class TrustDeviceBodyDTO extends createZodDto(EmptyBodySchema) {} // Re-using for trust/untrust
export class UntrustDeviceBodyDTO extends createZodDto(EmptyBodySchema) {}
