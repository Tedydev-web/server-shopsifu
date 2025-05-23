import { Request } from 'express'
import { REQUEST_USER_KEY } from '../constants/auth.constant'
import { AuditLogStatus, AuditLogData } from 'src/routes/audit-log/audit-log.service'
import { AccessTokenPayload } from '../types/jwt.type'
import { isObject, normalizeErrorMessage, isApiException } from './type-guards.utils'
import { safeStringify } from './validation.utils'

export interface CreateAuditLogOptions {
  action: string
  status?: AuditLogStatus
  entity?: string
  entityId?: string | number
  details?: Record<string, any>
  errorMessage?: string
  notes?: string
  maskSensitiveData?: boolean
  includeRequest?: boolean
  includeRequestBody?: boolean
  sensitiveFields?: string[]
}

export interface AuditLogContext {
  request?: Request
  userId?: number
  userEmail?: string
  error?: any
  result?: any
}

export const DEFAULT_SENSITIVE_FIELDS = [
  'password',
  'passwordConfirm',
  'currentPassword',
  'newPassword',
  'confirmPassword',
  'secret',
  'token',
  'accessToken',
  'refreshToken',
  'creditCard',
  'ccv',
  'pin',
  'otp',
  'twoFactorSecret'
]

export function createAuditLog(context: AuditLogContext, options: CreateAuditLogOptions): AuditLogData {
  const { request, userId, userEmail, error } = context
  const {
    action,
    status = error ? AuditLogStatus.FAILURE : AuditLogStatus.SUCCESS,
    entity,
    entityId,
    details,
    errorMessage,
    notes,
    maskSensitiveData = true,
    includeRequest = true,
    includeRequestBody = false,
    sensitiveFields = DEFAULT_SENSITIVE_FIELDS
  } = options

  const auditLogData: AuditLogData = {
    action: status === AuditLogStatus.FAILURE ? `${action}_FAILED` : action,
    status
  }

  if (userId) {
    auditLogData.userId = userId
  } else if (request?.[REQUEST_USER_KEY]) {
    const user = request[REQUEST_USER_KEY] as AccessTokenPayload
    auditLogData.userId = user.userId
  }

  if (userEmail) {
    auditLogData.userEmail = userEmail
  }

  if (entity) {
    auditLogData.entity = entity
  }

  if (entityId) {
    auditLogData.entityId = entityId
  }

  const detailsObject: Record<string, any> = details ? { ...details } : {}

  if (includeRequest && request) {
    const requestDetails: Record<string, any> = {
      path: request.path,
      method: request.method,
      query: isObject(request.query) ? request.query : undefined,
      params: isObject(request.params) ? request.params : undefined
    }

    if (includeRequestBody && request.body) {
      requestDetails.body = maskSensitiveData ? maskSensitiveFields(request.body, sensitiveFields) : request.body
    }

    detailsObject.request = requestDetails
  }

  if (error) {
    if (!errorMessage) {
      const normalizedError = normalizeErrorMessage(error)
      auditLogData.errorMessage = normalizedError.message

      if (normalizedError.details) {
        detailsObject.errorDetails = normalizedError.details
      }
    } else {
      auditLogData.errorMessage = errorMessage
    }
  }

  if (notes) {
    auditLogData.notes = notes
  }

  if (request) {
    auditLogData.ipAddress = request.ip
    auditLogData.userAgent = request.headers['user-agent'] as string
  }

  auditLogData.details = Object.keys(detailsObject).length > 0 ? detailsObject : undefined

  return auditLogData
}

export function maskSensitiveFields(obj: any, sensitiveFields: string[] = DEFAULT_SENSITIVE_FIELDS): any {
  if (!isObject(obj) && !Array.isArray(obj)) {
    return obj
  }

  if (Array.isArray(obj)) {
    return obj.map((item) => maskSensitiveFields(item, sensitiveFields))
  }

  const result: Record<string, any> = {}

  for (const [key, value] of Object.entries(obj)) {
    if (
      sensitiveFields.some(
        (field) => key.toLowerCase() === field.toLowerCase() || key.toLowerCase().includes(field.toLowerCase())
      )
    ) {
      result[key] = '[REDACTED]'
    } else if (isObject(value) || Array.isArray(value)) {
      result[key] = maskSensitiveFields(value, sensitiveFields)
    } else {
      result[key] = value
    }
  }

  return result
}

export function normalizeAuditLogDetails(details: Record<string, any>): Record<string, any> {
  if (!isObject(details)) {
    return {}
  }

  const result: Record<string, any> = {}

  for (const [key, value] of Object.entries(details)) {
    if (value === undefined) {
      continue
    } else if (value === null) {
      result[key] = null
    } else if (typeof value === 'function') {
      continue
    } else if (isObject(value) || Array.isArray(value)) {
      try {
        const normalizedValue = JSON.parse(safeStringify(value))
        result[key] = normalizedValue
      } catch {
        continue
      }
    } else {
      result[key] = value
    }
  }

  return result
}

export function extractUserFromRequest(req: Request): { userId?: number; userEmail?: string } {
  if (!req) {
    return {}
  }

  const user = req[REQUEST_USER_KEY] as AccessTokenPayload | undefined
  if (!user) {
    return {}
  }

  return {
    userId: user.userId
  }
}

export function normalizeErrorForAuditLog(error: any): { message: string; details?: Record<string, any> } {
  if (isApiException(error)) {
    return {
      message: error.message,
      details: { code: error.errorCode, apiErrorDetails: error.details }
    }
  }

  if (error instanceof Error) {
    return {
      message: error.message,
      details: error.stack ? { stack: error.stack.split('\n').slice(0, 3).join('\n') } : undefined
    }
  }

  if (isObject(error)) {
    return {
      message: error.message || 'Unknown error',
      details: { ...error }
    }
  }

  return {
    message: String(error || 'Unknown error')
  }
}
