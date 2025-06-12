export interface PermissionDefinition {
  subject: string
  action: string
  description?: string
  uiPath?: string
  isSystemPermission?: boolean
  conditions?: Record<string, any>
}
