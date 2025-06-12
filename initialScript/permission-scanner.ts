import * as path from 'path'
import * as fs from 'fs'
import { glob } from 'glob'
import * as ts from 'typescript'

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
   * Scan toàn bộ codebase để tìm permissions được định nghĩa qua @RequirePermissions.
   */
  async scanPermissions(): Promise<ScannedPermission[]> {
    this.scannedPermissions.clear()
    this.permissionsList = []

    const files = await glob('**/src/**/*.controller.ts', {
      cwd: process.cwd(),
      ignore: ['**/*.spec.ts', '**/*.test.ts', '**/node_modules/**']
    })

    console.log(`📁 Found ${files.length} controller files to scan.`)

    for (const file of files) {
      await this.scanFile(file)
    }

    console.log(`✅ Scan completed! Found ${this.permissionsList.length} unique permissions.`)
    return this.permissionsList
  }

  /**
   * Scan một file cụ thể để tìm decorators.
   */
  private async scanFile(filePath: string): Promise<void> {
    try {
      const content = await fs.promises.readFile(filePath, 'utf-8')
      const sourceFile = ts.createSourceFile(filePath, content, ts.ScriptTarget.Latest, true)
      this.visitNode(sourceFile)
    } catch (error) {
      console.warn(`⚠️  Could not scan file ${filePath}:`, error.message)
    }
  }

  /**
   * Duyệt qua các node trong AST của file để tìm decorator @RequirePermissions.
   */
  private visitNode(node: ts.Node): void {
    if (ts.isDecorator(node) && ts.isCallExpression(node.expression)) {
      const callExpr = node.expression
      if (ts.isIdentifier(callExpr.expression) && callExpr.expression.text === 'RequirePermissions') {
        this.extractFromRequirePermissions(callExpr)
      }
    }
    ts.forEachChild(node, (child) => this.visitNode(child))
  }

  /**
   * Trích xuất thông tin quyền từ decorator.
   */
  private extractFromRequirePermissions(node: ts.CallExpression): void {
    if (node.arguments.length === 0 || !ts.isArrayLiteralExpression(node.arguments[0])) {
      return
    }

    const permissionsArray = node.arguments[0]
    permissionsArray.elements.forEach((element) => {
      if (ts.isStringLiteral(element)) {
        const permissionString = element.text
        const [subject, action] = this.parsePermissionString(permissionString)

        if (subject && action) {
          const permission: ScannedPermission = {
            action,
            subject,
            description: this.generateDescription(action, subject),
            filePath: node.getSourceFile().fileName,
            lineNumber: this.getLineNumber(node)
          }
          this.addPermission(permission)
        }
      }
    })
  }

  /**
   * Phân tích chuỗi quyền thành subject và action.
   * Hỗ trợ định dạng 'Subject:action' và 'Subject:action:own'.
   */
  private parsePermissionString(permissionString: string): [string | null, string | null] {
    const parts = permissionString.split(':')
    if (parts.length >= 2) {
      const subject = parts[0]
      const action = parts.length === 3 && parts[2] === 'own' ? `${parts[1]}:${parts[2]}` : parts[1]
      return [subject, action]
    }
    return [null, null]
  }

  /**
   * Tạo mô tả cho quyền.
   */
  private generateDescription(action: string, subject: string): string {
    const actionDesc = action
      .replace(/([A-Z])/g, ' $1')
      .replace(':', ' ')
      .toLowerCase()
    return `Allows user to ${actionDesc} a ${subject}.`
  }

  /**
   * Lấy số dòng của node.
   */
  private getLineNumber(node: ts.Node): number {
    const sourceFile = node.getSourceFile()
    return sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1
  }

  /**
   * Thêm quyền vào danh sách và tránh trùng lặp.
   */
  private addPermission(permission: ScannedPermission): void {
    const key = `${permission.subject}:${permission.action}`
    if (!this.scannedPermissions.has(key)) {
      this.scannedPermissions.add(key)
      this.permissionsList.push(permission)
      console.log(`  ✓ Found: ${key.padEnd(30)} in ${path.basename(permission.filePath)}:${permission.lineNumber}`)
    }
  }

  /**
   * Tạo danh sách quyền để seed vào database.
   */
  generatePermissionsForSeeding(): Array<{
    action: string
    subject: string
    description: string
  }> {
    const permissions = [
      {
        action: 'manage',
        subject: 'all',
        description: 'Grants full access to all resources. For Admin role only.'
      }
    ]

    this.permissionsList.forEach((p) => {
      permissions.push({
        action: p.action,
        subject: p.subject,
        description: p.description
      })
    })

    // Thêm các quyền sở hữu một cách tường minh
    const ownershipPermissions = this.permissionsList
      .filter((p) => p.action.endsWith(':own'))
      .map((p) => ({
        action: p.action,
        subject: p.subject,
        description: p.description
      }))

    for (const op of ownershipPermissions) {
      if (!permissions.some((p) => p.subject === op.subject && p.action === op.action)) {
        permissions.push(op)
      }
    }

    return permissions
  }
}
