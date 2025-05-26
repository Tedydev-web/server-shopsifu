import { z } from 'zod'
import { createZodDto } from 'nestjs-zod'
import { EmptyBodySchema } from 'src/shared/models/request.model'
import { createPaginatedResponseSchema } from 'src/shared/models/pagination.model'

const BaseDeviceSchema = z.object({
  id: z.number().int(),
  name: z.string().nullable().describe('User-assigned name for the device'),
  type: z.enum(['desktop', 'mobile', 'tablet', 'wearable', 'tv', 'console', 'unknown']),
  os: z.string().nullable().describe('Operating System'),
  browser: z.string().nullable().describe('Browser name')
})

const ActiveSessionDeviceSchema = BaseDeviceSchema.extend({
  isCurrentDevice: z.boolean().describe('Is this the device making the current request?')
})

export const ActiveSessionSchema = z.object({
  sessionId: z.string().uuid(),
  device: ActiveSessionDeviceSchema,
  ipAddress: z.string().nullable(),
  location: z.string().nullable().describe('Approximate location, e.g., City, Country'),
  loggedInAt: z.string(),
  lastActiveAt: z.string(),
  isCurrentSession: z.boolean().describe('Is this the session of the current request?')
})

export const GetActiveSessionsResSchema = createPaginatedResponseSchema(ActiveSessionSchema)

export class GetActiveSessionsResDTO extends createZodDto(GetActiveSessionsResSchema) {}

export const GetActiveSessionsQuerySchema = z.object({
  deviceId: z.coerce.number().int().positive().optional().describe('Filter sessions by a specific device ID.')
})

export class GetActiveSessionsQueryDTO extends createZodDto(GetActiveSessionsQuerySchema) {}

export const RevokeSessionParamsSchema = z.object({
  sessionId: z.string().uuid().describe('The UUID of the session to revoke')
})

export class RevokeSessionParamsDTO extends createZodDto(RevokeSessionParamsSchema) {}

export const DeviceInfoSchema = BaseDeviceSchema.extend({
  ip: z.string().optional().nullable(),
  location: z.string().optional().nullable(),
  createdAt: z.string().optional(),
  lastActive: z.string().optional(),
  isTrusted: z.boolean(),
  isCurrentDevice: z.boolean().optional()
})

export const GetDevicesResSchema = createPaginatedResponseSchema(DeviceInfoSchema)

export class GetDevicesResDTO extends createZodDto(GetDevicesResSchema) {}

export const DeviceIdParamsSchema = z.object({
  deviceId: z.coerce.number().int().positive()
})

export const UpdateDeviceNameBodySchema = z.object({
  name: z.string().min(1).max(255).trim()
})

export class DeviceIdParamsDTO extends createZodDto(DeviceIdParamsSchema) {}
export class UpdateDeviceNameBodyDTO extends createZodDto(UpdateDeviceNameBodySchema) {}
export class TrustDeviceBodyDTO extends createZodDto(EmptyBodySchema) {}
export class UntrustDeviceBodyDTO extends createZodDto(EmptyBodySchema) {}

export const RevokeSessionsBodySchema = z
  .object({
    sessionIds: z.array(z.string().uuid()).optional().describe('Array of session UUIDs to revoke.'),
    deviceId: z.number().int().positive().optional().describe('Revoke all sessions for this device ID and untrust it.'),
    revokeAll: z
      .boolean()
      .optional()
      .default(false)
      .describe('Revoke all sessions for the user except the current one.')
  })
  .strict()
  .refine(
    (data) => {
      const providedOptions = [data.sessionIds, data.deviceId, data.revokeAll].filter(
        (opt) => opt !== undefined && opt !== false && (!Array.isArray(opt) || opt.length > 0)
      ).length
      return providedOptions === 1
    },
    {
      message: 'Exactly one of sessionIds, deviceId, or revokeAll must be provided and be valid.',
      path: [] // General error for the whole object
    }
  )

export class RevokeSessionsBodyDTO extends createZodDto(RevokeSessionsBodySchema) {}
