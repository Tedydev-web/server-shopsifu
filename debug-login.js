const { PrismaClient } = require('@prisma/client')
const bcrypt = require('bcrypt')

const prisma = new PrismaClient()

async function debugLogin() {
  try {
    console.log('🔍 Debugging login for: shopsifu.ecommerce@gmail.com')

    // 1. Kiểm tra user có tồn tại không
    const user = await prisma.user.findUnique({
      where: { email: 'shopsifu.ecommerce@gmail.com' },
      include: { role: true },
    })

    if (!user) {
      console.log('❌ User not found in database')
      return
    }

    console.log('✅ User found:')
    console.log('  - ID:', user.id)
    console.log('  - Email:', user.email)
    console.log('  - Name:', user.name)
    console.log('  - Status:', user.status)
    console.log('  - Role ID:', user.roleId)
    console.log('  - Role:', user.role?.name)
    console.log('  - Password hash (first 20 chars):', user.password.substring(0, 20) + '...')

    // 2. Kiểm tra status
    if (user.status !== 'ACTIVE') {
      console.log('❌ User status is not ACTIVE:', user.status)
      return
    }

    console.log('✅ User status is ACTIVE')

    // 3. Test password hash
    const testPassword = 'Shopsifu2025@@'
    console.log('🔑 Testing password:', testPassword)

    const isMatch = await bcrypt.compare(testPassword, user.password)
    console.log('🔑 Password match result:', isMatch)

    if (!isMatch) {
      console.log('❌ Password does not match!')

      // Test với một số variations
      const variations = ['Shopsifu2025@', 'shopsifu2025@@', 'Shopsifu2025', 'Super Admin', user.name]

      console.log('🔑 Testing password variations...')
      for (const variation of variations) {
        const testResult = await bcrypt.compare(variation, user.password)
        console.log(`  - "${variation}": ${testResult}`)
      }
    } else {
      console.log('✅ Password matches!')
    }

    // 4. Kiểm tra findActiveUserByEmail method
    console.log('\n🔍 Testing findActiveUserByEmail method...')
    const activeUser = await prisma.user.findFirst({
      where: {
        email: 'shopsifu.ecommerce@gmail.com',
        status: 'ACTIVE',
      },
    })

    if (activeUser) {
      console.log('✅ findActiveUserByEmail would return user')
    } else {
      console.log('❌ findActiveUserByEmail would return null')
    }
  } catch (error) {
    console.error('💥 Error:', error)
  } finally {
    await prisma.$disconnect()
  }
}

debugLogin()
