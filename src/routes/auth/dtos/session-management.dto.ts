import { z } from 'zod'
import { createZodDto } from 'nestjs-zod'
import { EmptyBodySchema } from 'src/shared/models/request.model'
import { createPaginatedResponseSchema } from 'src/shared/models/pagination.model'
import { BasePaginationQuerySchema } from 'src/shared/models/pagination.model'
import { MessageResSchema } from 'src/shared/models/response.model'

const BaseDeviceSchema = z.object({
  id: z.number().int(),
  name: z.string().nullable().describe('User-assigned name for the device'),
  type: z.enum(['desktop', 'mobile', 'tablet', 'wearable', 'tv', 'console', 'unknown']),
  os: z.string().nullable().describe('Operating System'),
  browser: z.string().nullable().describe('Browser name')
})

export const NestedSessionSchema = z.object({
  sessionId: z.string().uuid(),
  ipAddress: z.string().ip().nullable().describe('IP address of this session'),
  location: z.string().nullable().describe('Approximate location of this session'),
  loggedInAt: z.string().datetime().describe('Timestamp when this session was created'),
  lastActiveAt: z.string().datetime().describe('Timestamp when this session was last active'),
  isCurrentSession: z.boolean().describe('Is this the session of the current request?')
})

export const DeviceWithSessionsSchema = BaseDeviceSchema.extend({
  firstSeenAt: z.string().datetime().describe('Timestamp when this device was first recorded for the user'),
  lastSeenAt: z.string().datetime().describe('Timestamp when this device was last active overall for the user'),
  isTrusted: z.boolean().describe('Whether this device is marked as trusted by the user'),
  isCurrentDevice: z.boolean().describe('Is this the device making the current request?'),
  sessions: z.array(NestedSessionSchema).describe('List of active sessions on this device')
})

export const GetSessionsGroupedByDeviceResSchema = createPaginatedResponseSchema(DeviceWithSessionsSchema)

export class GetSessionsGroupedByDeviceResDTO extends createZodDto(GetSessionsGroupedByDeviceResSchema) {}

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

export const GetSessionsByDeviceQuerySchema = BasePaginationQuerySchema.extend({
  sortBy: z
    .enum(['lastSeenAt', 'firstSeenAt', 'name'])
    .default('lastSeenAt')
    .optional()
    .describe('Field to sort devices by. lastSeenAt recommended for chronological view of recent devices.')
})

export class GetSessionsByDeviceQueryDTO extends createZodDto(GetSessionsByDeviceQuerySchema) {}

export const GetActiveSessionsQuerySchema = z.object({
  deviceId: z.coerce
    .number()
    .int()
    .positive()
    .optional()
    .describe(
      'Filter sessions by a specific device ID. This will likely be deprecated if sessions are always grouped by device.'
    )
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
    sessionIds: z.array(z.string().uuid()).optional().describe('List of session IDs to revoke.'),
    deviceIds: z
      .array(z.number().int().positive())
      .min(1, { message: 'At least one device ID must be provided when using deviceIds.' })
      .optional(),
    untrustDevices: z.boolean().optional().default(true),
    revokeAll: z.boolean().optional()
  })
  .strict()
  .refine(
    (data) => {
      const providedOptions = [data.sessionIds, data.deviceIds, data.revokeAll].filter(
        (opt) => opt !== undefined && opt !== false && (!Array.isArray(opt) || opt.length > 0)
      ).length
      return providedOptions === 1
    },
    {
      message: 'Exactly one of sessionIds, deviceIds, or revokeAll must be provided and be valid.',
      path: []
    }
  )
  .superRefine((data, ctx) => {
    const { sessionIds, deviceIds, revokeAll } = data

    if (!sessionIds && !deviceIds && !revokeAll) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'At least one of sessionIds, deviceIds, or revokeAll must be provided.',
        path: []
      })
    }
  })

export class RevokeSessionsBodyDTO extends createZodDto(RevokeSessionsBodySchema) {}

export const RevokeSessionsResSchema = MessageResSchema.extend({
  requiresPasswordReverification: z.boolean().optional()
})

export class RevokeSessionsResDTO extends createZodDto(RevokeSessionsResSchema) {}
