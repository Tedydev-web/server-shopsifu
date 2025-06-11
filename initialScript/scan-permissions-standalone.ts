#!/usr/bin/env tsx
/**
 * Standalone Permission Scanner - for testing and debugging permission discovery
 */

import { PermissionScanner } from './permission-scanner'

async function main() {
  console.log('🔍 Standalone Permission Scanner')
  console.log('===============================\n')

  try {
    const scanner = new PermissionScanner()

    console.log('Starting permission scan...')
    const permissions = await scanner.scanPermissions()
    const permissionsToSeed = scanner.generatePermissionsForSeeding()

    console.log('\n📊 Permission Discovery Summary:')
    console.log(`Scanned permissions: ${permissions.length}`)
    console.log(`Total to seed (including manage:all): ${permissionsToSeed.length}`)

    // Group by category
    const byCategory = new Map<string, number>()
    permissions.forEach((permission) => {
      byCategory.set(permission.category, (byCategory.get(permission.category) || 0) + 1)
    })

    console.log('\nBy category:')
    byCategory.forEach((count, category) => {
      console.log(`  ${category}: ${count} permissions`)
    })

    console.log('\n📋 Found Permissions:')
    permissions.forEach((permission) => {
      console.log(`  🔐 ${permission.action}:${permission.subject} (${permission.category})`)
    })

    // Export to file
    await scanner.exportToFile('./initialScript/scanned-permissions.ts')
    console.log('\n✅ Results exported to scanned-permissions.ts')
  } catch (error) {
    console.error('❌ Error during permission scanning:', error.message)
    console.error('Stack:', error.stack)
    process.exit(1)
  }
}

void main()
