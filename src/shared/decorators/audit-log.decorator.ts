import { SetMetadata } from '@nestjs/common'
import { AuditLogStatus } from '../services/audit.service'

export const AUDIT_LOG_KEY = 'audit_log_metadata'

export interface AuditLogOptions {
  action: string
  entity?: string
  getEntityId?: (params: any[], result: any) => string | number | undefined
  getDetails?: (params: any[], result: any) => Record<string, any> | undefined
  getErrorDetails?: (params: any[], error: any) => Record<string, any> | undefined
  getUserId?: (params: any[]) => number | undefined
  getUserEmail?: (params: any[]) => string | undefined
  getNotes?: (params: any[], result: any) => string | undefined
  getErrorMessage?: (error: any) => string | undefined
}

/**
 * Decorator để đánh dấu một phương thức cần được ghi log audit
 * @param options Các tùy chọn cho việc ghi log
 * @example
 * ```typescript
 * @AuditLog({
 *   action: 'USER_LOGIN',
 *   entity: 'User',
 *   getUserId: (params) => params[0]?.userId,
 *   getEntityId: (params, result) => result?.userId,
 *   getDetails: (params, result) => ({ userRole: result?.role })
 * })
 * async login(credentials) { ... }
 * ```
 */
export const AuditLog = (options: AuditLogOptions) => SetMetadata(AUDIT_LOG_KEY, options)
