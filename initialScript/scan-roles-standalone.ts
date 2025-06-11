#!/usr/bin/env tsx
/**
 * Standalone Role Scanner - for testing and debugging role discovery
 */

import { RoleScanner } from './role-scanner'

async function main() {
  console.log('🔍 Standalone Role Scanner')
  console.log('==========================\n')

  const scanner = new RoleScanner()

  try {
    const roles = await scanner.scanRoles()

    console.log('\n📊 Role Discovery Summary:')
    console.log(`Total roles found: ${roles.length}`)

    // Group by source
    const bySource = new Map<string, number>()
    roles.forEach((role) => {
      bySource.set(role.foundIn, (bySource.get(role.foundIn) || 0) + 1)
    })

    console.log('\nBy source:')
    bySource.forEach((count, source) => {
      console.log(`  ${source}: ${count} roles`)
    })

    // Group by strategy
    const byStrategy = new Map<string, number>()
    roles.forEach((role) => {
      byStrategy.set(role.permissionStrategy, (byStrategy.get(role.permissionStrategy) || 0) + 1)
    })

    console.log('\nBy permission strategy:')
    byStrategy.forEach((count, strategy) => {
      console.log(`  ${strategy}: ${count} roles`)
    })

    console.log('\n📋 Role Details:')
    roles.forEach((role) => {
      console.log(`\n🏷️  ${role.name}`)
      console.log(`   Description: ${role.description}`)
      console.log(`   System Role: ${role.isSystemRole}`)
      console.log(`   Strategy: ${role.permissionStrategy}`)
      console.log(`   Permissions: ${role.permissions.length}`)
      console.log(`   Found in: ${role.foundIn}`)
      if (role.filePath) {
        console.log(`   File: ${role.filePath}`)
      }
    })

    // Export to file
    await scanner.exportToFile('./initialScript/scanned-roles-debug.ts')
    console.log('\n✅ Results exported to scanned-roles-debug.ts')
  } catch (error) {
    console.error('❌ Error during role scanning:', error)
    process.exit(1)
  }
}

main()
