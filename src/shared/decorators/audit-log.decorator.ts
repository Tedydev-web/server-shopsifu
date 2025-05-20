import { SetMetadata } from '@nestjs/common'

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

export const AuditLog = (options: AuditLogOptions) => SetMetadata(AUDIT_LOG_KEY, options)
