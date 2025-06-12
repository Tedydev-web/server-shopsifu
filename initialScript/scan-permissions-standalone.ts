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
    console.log(`Total to seed: ${permissionsToSeed.length}`)

    console.log('\n📋 Found Permissions:')
    permissions.forEach((permission) => {
      console.log(`  🔐 ${permission.action}:${permission.subject}`)
    })

    // Export to file
    console.log('\n✅ Results exported to scanned-permissions.ts')
  } catch (error) {
    console.error('❌ Error during permission scanning:', error.message)
    console.error('Stack:', error.stack)
    process.exit(1)
  }
}

void main()
