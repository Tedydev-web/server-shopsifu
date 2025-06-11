import * as fs from 'fs'
import * as path from 'path'
import { glob } from 'glob'
import * as ts from 'typescript'
import { PrismaClient } from '@prisma/client'

export interface ScannedRole {
  name: string
  description?: string
  isSystemRole: boolean
  permissionStrategy: 'ALL' | 'CUSTOM' | 'INHERIT'
  permissions: Array<{ action: string; subject: string }>
  foundIn: 'database' | 'code' | 'both'
  filePath?: string
  lineNumber?: number
}

export class RoleScanner {
  private readonly srcPath: string
  private readonly prisma: PrismaClient
  private scannedRoles: Map<string, ScannedRole> = new Map()

  constructor(projectRoot: string = process.cwd()) {
    this.srcPath = path.join(projectRoot, 'src')
    this.prisma = new PrismaClient()
  }

  /**
   * Scan toàn bộ hệ thống để tìm roles
   */
  async scanRoles(): Promise<ScannedRole[]> {
    console.log('🔍 Starting role scanning...')

    this.scannedRoles.clear()

    // 1. Scan database for existing roles
    await this.scanDatabaseRoles()

    // 2. Scan codebase for role references
    await this.scanCodebaseRoles()

    // 3. Apply smart defaults và infer permissions
    await this.applySmartDefaults()

    const roles = Array.from(this.scannedRoles.values())
    console.log(`✅ Role scan completed! Found ${roles.length} unique roles`)

    return roles
  }

  /**
   * Scan database cho roles hiện có
   */
  private async scanDatabaseRoles(): Promise<void> {
    try {
      await this.prisma.$connect()

      const dbRoles = await this.prisma.role.findMany({
        include: {
          permissions: {
            include: {
              permission: true
            }
          }
        }
      })

      console.log(`📊 Found ${dbRoles.length} roles in database`)

      for (const role of dbRoles) {
        const permissions = role.permissions.map((rp) => ({
          action: rp.permission.action,
          subject: rp.permission.subject
        }))

        this.scannedRoles.set(role.name, {
          name: role.name,
          description: role.description || undefined,
          isSystemRole: role.isSystemRole,
          permissionStrategy: this.inferPermissionStrategy(role.name, permissions),
          permissions,
          foundIn: 'database'
        })

        console.log(`  ✓ Database role: ${role.name} (${permissions.length} permissions)`)
      }
    } catch (error) {
      console.warn('⚠️  Could not scan database roles:', error.message)
    } finally {
      await this.prisma.$disconnect()
    }
  }

  /**
   * Scan codebase cho role references
   */
  private async scanCodebaseRoles(): Promise<void> {
    try {
      const files = await glob('**/*.{ts,js}', {
        cwd: this.srcPath,
        ignore: ['**/*.spec.ts', '**/*.test.ts', '**/node_modules/**']
      })

      console.log(`📁 Scanning ${files.length} files for role references`)

      for (const file of files) {
        const filePath = path.join(this.srcPath, file)
        await this.scanFileForRoles(filePath)
      }
    } catch (error) {
      console.warn('⚠️  Could not scan codebase for roles:', error.message)
    }
  }

  /**
   * Scan một file cho role references
   */
  private async scanFileForRoles(filePath: string): Promise<void> {
    try {
      const content = await fs.promises.readFile(filePath, 'utf-8')

      // Simple regex patterns for common role patterns
      const rolePatterns = [
        /role[:\s]*['"`](\w+)['"`]/gi,
        /roleName[:\s]*['"`](\w+)['"`]/gi,
        /name[:\s]*['"`](\w+)['"`]/gi, // In role files
        /'(\w+)'\s*role/gi,
        /ROLE_(\w+)/gi,
        /AppRole\.(\w+)/gi
      ]

      const roleNames = new Set<string>()

      for (const pattern of rolePatterns) {
        let match
        while ((match = pattern.exec(content)) !== null) {
          const roleName = match[1]
          if (this.isValidRoleName(roleName)) {
            roleNames.add(roleName)
          }
        }
      }

      // Update found roles
      for (const roleName of roleNames) {
        if (this.scannedRoles.has(roleName)) {
          const role = this.scannedRoles.get(roleName)!
          role.foundIn = role.foundIn === 'database' ? 'both' : 'code'
          if (!role.filePath) {
            role.filePath = filePath
          }
        } else {
          // New role found in code
          this.scannedRoles.set(roleName, {
            name: roleName,
            description: `${roleName} role (auto-detected)`,
            isSystemRole: this.inferIsSystemRole(roleName),
            permissionStrategy: 'CUSTOM',
            permissions: [],
            foundIn: 'code',
            filePath
          })

          console.log(`  ✓ Code role: ${roleName} in ${path.basename(filePath)}`)
        }
      }
    } catch (error) {
      console.warn(`⚠️  Could not scan file ${filePath}:`, error.message)
    }
  }

  /**
   * Apply smart defaults và infer permissions
   */
  private async applySmartDefaults(): Promise<void> {
    console.log('\n🧠 Applying smart defaults...')

    for (const [roleName, role] of this.scannedRoles) {
      // Ensure Admin role has ALL permissions
      if (roleName.toLowerCase() === 'admin') {
        role.permissionStrategy = 'ALL'
        role.isSystemRole = true
        role.description = role.description || 'Administrator with full system access'
        console.log(`  ✓ Admin role: Set to ALL permissions`)
      }

      // Apply defaults for common roles
      if (roleName.toLowerCase() === 'customer') {
        role.description = role.description || 'Standard customer account'
        role.isSystemRole = false
        if (role.permissions.length === 0) {
          role.permissions = this.getDefaultCustomerPermissions()
        }
        console.log(`  ✓ Customer role: Applied default permissions`)
      }

      if (roleName.toLowerCase() === 'seller') {
        role.description = role.description || 'Vendor/Seller account with product management'
        role.isSystemRole = false
        if (role.permissions.length === 0) {
          role.permissions = this.getDefaultSellerPermissions()
        }
        console.log(`  ✓ Seller role: Applied default permissions`)
      }

      // Generate description if missing
      if (!role.description) {
        role.description = `${roleName} role`
      }
    }
  }

  /**
   * Check if role name is valid
   */
  private isValidRoleName(roleName: string): boolean {
    // Filter out common false positives
    const invalidNames = [
      'string',
      'boolean',
      'number',
      'object',
      'array',
      'null',
      'undefined',
      'true',
      'false',
      // Error constants and technical terms
      'NOT_FOUND',
      'ALREADY_EXISTS',
      'CREATE_FAILED',
      'UPDATE_FAILED',
      'DELETE_FAILED',
      'BAD_REQUEST',
      'UNAUTHORIZED',
      'FORBIDDEN',
      'INTERNAL_ERROR',
      'CACHE_TTL',
      'SUCCESS',
      'ERROR',
      'PENDING',
      'ACTIVE',
      'INACTIVE',
      'EXPIRED',
      // Common constants
      'DEFAULT',
      'CONFIG',
      'SETTINGS',
      'OPTIONS',
      'PARAMS',
      'ARGS',
      'DATA',
      // Status codes
      'OK',
      'FAIL',
      'TIMEOUT',
      'RETRY',
      'CANCEL'
    ]

    // Must be reasonable length
    if (roleName.length < 3 || roleName.length > 50) {
      return false
    }

    // Don't include obvious non-roles
    if (invalidNames.includes(roleName.toUpperCase())) {
      return false
    }

    // Must be alphanumeric with optional underscores
    if (!/^[a-zA-Z][a-zA-Z0-9_]*$/.test(roleName)) {
      return false
    }

    // Filter out all-caps constants (likely not roles)
    if (roleName === roleName.toUpperCase() && roleName.includes('_')) {
      return false
    }

    return true
  }

  /**
   * Infer if role is system role based on name
   */
  private inferIsSystemRole(roleName: string): boolean {
    const systemRolePatterns = ['admin', 'system', 'root', 'superuser', 'super']
    return systemRolePatterns.some((pattern) => roleName.toLowerCase().includes(pattern))
  }

  /**
   * Infer permission strategy
   */
  private inferPermissionStrategy(
    roleName: string,
    permissions: Array<{ action: string; subject: string }>
  ): 'ALL' | 'CUSTOM' {
    if (roleName.toLowerCase() === 'admin' || permissions.some((p) => p.action === 'manage' && p.subject === 'all')) {
      return 'ALL'
    }
    return 'CUSTOM'
  }

  /**
   * Get default customer permissions
   */
  private getDefaultCustomerPermissions(): Array<{ action: string; subject: string }> {
    return [
      // Auth permissions
      { action: 'login', subject: 'Auth' },
      { action: 'register', subject: 'Auth' },
      { action: 'refresh', subject: 'Auth' },
      { action: 'logout', subject: 'Auth' },
      { action: 'verify_otp', subject: 'Auth' },
      { action: 'send_otp', subject: 'Auth' },
      { action: 'reset_password', subject: 'Auth' },
      { action: 'link_social', subject: 'Auth' },

      // Profile permissions
      { action: 'read', subject: 'UserProfile' },
      { action: 'update', subject: 'UserProfile' },

      // Device permissions
      { action: 'read', subject: 'Device' },
      { action: 'update', subject: 'Device' },
      { action: 'delete', subject: 'Device' },

      // Catalog permissions
      { action: 'read', subject: 'Product' },
      { action: 'read', subject: 'Category' },
      { action: 'read', subject: 'Brand' }
    ]
  }

  /**
   * Get default seller permissions
   */
  private getDefaultSellerPermissions(): Array<{ action: string; subject: string }> {
    return [
      // Include all customer permissions
      ...this.getDefaultCustomerPermissions(),

      // Additional seller permissions
      { action: 'create', subject: 'Product' },
      { action: 'update', subject: 'Product' },
      { action: 'read', subject: 'Order' }
    ]
  }

  /**
   * Export roles ra file để review
   */
  async exportToFile(outputPath: string): Promise<void> {
    const roles = Array.from(this.scannedRoles.values())
    const content = `// Auto-generated roles from scanning database and codebase
// Generated at: ${new Date().toISOString()}
// Total roles found: ${roles.length}

export const SCANNED_ROLES = ${JSON.stringify(roles, null, 2)} as const;

// Breakdown by source:
${this.generateSourceBreakdown()}

// Role strategies:
${this.generateStrategyBreakdown()}
`

    await fs.promises.writeFile(outputPath, content, 'utf-8')
    console.log(`📄 Roles exported to: ${outputPath}`)
  }

  /**
   * Generate source breakdown
   */
  private generateSourceBreakdown(): string {
    const sources = new Map<string, number>()

    this.scannedRoles.forEach((role) => {
      sources.set(role.foundIn, (sources.get(role.foundIn) || 0) + 1)
    })

    let breakdown = ''
    sources.forEach((count, source) => {
      breakdown += `// ${source}: ${count} roles\n`
    })

    return breakdown
  }

  /**
   * Generate strategy breakdown
   */
  private generateStrategyBreakdown(): string {
    const strategies = new Map<string, number>()

    this.scannedRoles.forEach((role) => {
      strategies.set(role.permissionStrategy, (strategies.get(role.permissionStrategy) || 0) + 1)
    })

    let breakdown = ''
    strategies.forEach((count, strategy) => {
      breakdown += `// ${strategy}: ${count} roles\n`
    })

    return breakdown
  }
}
