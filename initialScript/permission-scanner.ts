import * as fs from 'fs'
import * as path from 'path'
import { glob } from 'glob'
import * as ts from 'typescript'
import { Action } from '../src/shared/providers/casl/casl-ability.factory'

export interface ScannedPermission {
  action: string
  subject: string
  category?: string
  description?: string
  filePath: string
  lineNumber: number
}

export class PermissionScanner {
  private readonly srcPath: string
  private scannedPermissions: Set<string> = new Set()
  private permissionsList: ScannedPermission[] = []

  constructor(projectRoot: string = process.cwd()) {
    this.srcPath = path.join(projectRoot, 'src')
  }

  /**
   * Scan toàn bộ codebase để tìm permissions
   */
  async scanPermissions(): Promise<ScannedPermission[]> {
    console.log('🔍 Starting permission scanning...')

    // Reset data
    this.scannedPermissions.clear()
    this.permissionsList = []

    // Tìm tất cả file TypeScript
    const files = await glob('**/*.{ts,js}', {
      cwd: this.srcPath,
      ignore: ['**/*.spec.ts', '**/*.test.ts', '**/node_modules/**']
    })

    console.log(`📁 Found ${files.length} files to scan`)

    for (const file of files) {
      const filePath = path.join(this.srcPath, file)
      await this.scanFile(filePath)
    }

    console.log(`✅ Scan completed! Found ${this.permissionsList.length} unique permissions`)
    return this.permissionsList
  }

  /**
   * Scan một file cụ thể
   */
  private async scanFile(filePath: string): Promise<void> {
    try {
      const content = await fs.promises.readFile(filePath, 'utf-8')
      const sourceFile = ts.createSourceFile(filePath, content, ts.ScriptTarget.Latest, true)

      this.visitNode(sourceFile, filePath)
    } catch (error) {
      console.warn(`⚠️  Could not scan file ${filePath}:`, error.message)
    }
  }

  /**
   * Duyệt AST nodes để tìm permissions
   */
  private visitNode(node: ts.Node, filePath: string): void {
    // Tìm CheckAbilities calls
    if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === 'CheckAbilities') {
      this.extractFromCheckAbilities(node, filePath)
    }

    // Tìm ability.can() calls
    if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
      if (node.expression.name.text === 'can') {
        this.extractFromAbilityCan(node, filePath)
      }
    }

    // Tìm trong object literals (cho policy definitions)
    if (ts.isObjectLiteralExpression(node)) {
      this.extractFromObjectLiteral(node, filePath)
    }

    // Đệ quy cho các node con
    ts.forEachChild(node, (child) => this.visitNode(child, filePath))
  }

  /**
   * Extract permissions từ CheckAbilities calls
   */
  private extractFromCheckAbilities(node: ts.CallExpression, filePath: string): void {
    node.arguments.forEach((arg) => {
      if (ts.isObjectLiteralExpression(arg)) {
        const permission = this.extractPermissionFromObject(arg, filePath)
        if (permission) {
          this.addPermission(permission)
        }
      }
    })
  }

  /**
   * Extract permissions từ ability.can() calls
   */
  private extractFromAbilityCan(node: ts.CallExpression, filePath: string): void {
    if (node.arguments.length >= 2) {
      const actionArg = node.arguments[0]
      const subjectArg = node.arguments[1]

      const action = this.extractStringValue(actionArg)
      const subject = this.extractStringValue(subjectArg)

      if (action && subject) {
        const permission: ScannedPermission = {
          action,
          subject,
          category: this.inferCategory(subject, filePath),
          description: `${action} permission for ${subject}`,
          filePath,
          lineNumber: this.getLineNumber(node, filePath)
        }
        this.addPermission(permission)
      }
    }
  }

  /**
   * Extract permissions từ object literals
   */
  private extractFromObjectLiteral(node: ts.ObjectLiteralExpression, filePath: string): void {
    const permission = this.extractPermissionFromObject(node, filePath)
    if (permission) {
      this.addPermission(permission)
    }
  }

  /**
   * Extract permission từ object literal
   */
  private extractPermissionFromObject(node: ts.ObjectLiteralExpression, filePath: string): ScannedPermission | null {
    let action: string | null = null
    let subject: string | null = null

    for (const property of node.properties) {
      if (ts.isPropertyAssignment(property) && ts.isIdentifier(property.name)) {
        const propName = property.name.text
        const value = this.extractStringValue(property.initializer)

        if (propName === 'action' && value) {
          action = value
        } else if (propName === 'subject' && value) {
          subject = value
        }
      }
    }

    if (action && subject) {
      return {
        action,
        subject,
        category: this.inferCategory(subject, filePath),
        description: `${action} permission for ${subject}`,
        filePath,
        lineNumber: this.getLineNumber(node, filePath)
      }
    }

    return null
  }

  /**
   * Extract string value từ expression
   */
  private extractStringValue(node: ts.Expression): string | null {
    if (ts.isStringLiteral(node)) {
      return node.text
    }

    if (ts.isPropertyAccessExpression(node)) {
      // Handle Action.Create, Action.Read, etc.
      if (ts.isIdentifier(node.expression) && node.expression.text === 'Action') {
        return node.name.text.toLowerCase()
      }
    }

    if (ts.isIdentifier(node)) {
      // Handle direct identifiers
      return node.text
    }

    return null
  }

  /**
   * Lấy line number của node
   */
  private getLineNumber(node: ts.Node, filePath: string): number {
    const sourceFile = node.getSourceFile()
    return sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1
  }

  /**
   * Infer category từ subject và file path
   */
  private inferCategory(subject: string, filePath: string): string {
    // Auth related
    if (subject.toLowerCase().includes('auth') || filePath.includes('/auth/')) {
      return 'Authentication'
    }

    // User management
    if (subject === 'User' || subject === 'UserProfile') {
      return 'User Management'
    }

    // Role management
    if (subject === 'Role') {
      return 'Role Management'
    }

    // Permission management
    if (subject === 'Permission') {
      return 'Permission Management'
    }

    // Device/Session management
    if (subject === 'Device' || filePath.includes('/session')) {
      return 'Device Management'
    }

    // E-commerce related
    if (['Product', 'Category', 'Order', 'Brand', 'Variant', 'SKU', 'CartItem', 'Review'].includes(subject)) {
      return 'E-commerce'
    }

    // Default category
    return 'General'
  }

  /**
   * Add permission to list (avoid duplicates)
   */
  private addPermission(permission: ScannedPermission): void {
    const key = `${permission.action}:${permission.subject}`

    if (!this.scannedPermissions.has(key)) {
      this.scannedPermissions.add(key)
      this.permissionsList.push(permission)
      console.log(
        `  ✓ Found permission: ${permission.action} on ${permission.subject} in ${path.basename(permission.filePath)}:${permission.lineNumber}`
      )
    }
  }

  /**
   * Generate permissions theo format cần thiết cho seeding
   */
  generatePermissionsForSeeding(): Array<{
    action: string
    subject: string
    category: string
    description: string
  }> {
    // Add manage:all permission for admin
    const permissions = [
      {
        action: 'manage',
        subject: 'all',
        category: 'System',
        description: 'Full access to all resources (Admin only)'
      }
    ]

    // Add scanned permissions
    this.permissionsList.forEach((permission) => {
      permissions.push({
        action: permission.action,
        subject: permission.subject,
        category: permission.category || 'General',
        description: permission.description || `${permission.action} permission for ${permission.subject}`
      })
    })

    return permissions
  }

  /**
   * Export ra file để review
   */
  async exportToFile(outputPath: string): Promise<void> {
    const permissions = this.generatePermissionsForSeeding()
    const content = `// Auto-generated permissions from scanning codebase
// Generated at: ${new Date().toISOString()}
// Total permissions found: ${permissions.length}

export const SCANNED_PERMISSIONS = ${JSON.stringify(permissions, null, 2)} as const;

// Breakdown by category:
${this.generateCategoryBreakdown()}
`

    await fs.promises.writeFile(outputPath, content, 'utf-8')
    console.log(`📄 Permissions exported to: ${outputPath}`)
  }

  /**
   * Generate category breakdown for documentation
   */
  private generateCategoryBreakdown(): string {
    const categories = new Map<string, number>()

    this.permissionsList.forEach((permission) => {
      const category = permission.category || 'General'
      categories.set(category, (categories.get(category) || 0) + 1)
    })

    let breakdown = ''
    categories.forEach((count, category) => {
      breakdown += `// ${category}: ${count} permissions\n`
    })

    return breakdown
  }
}
