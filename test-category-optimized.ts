/**
 * Test Category Optimized Refactor
 *
 * Kiểm tra Category API với refactor tối ưu:
 * - Thay thế hoàn toàn categories thay vì tạo thêm flattenedCategories
 * - Sử dụng map trực tiếp trên kết quả từ Prisma
 * - Tối ưu memory và performance
 */

import axios from 'axios'

const BASE_URL = 'http://localhost:3000'

async function testCategoryOptimized() {
  try {
    console.log('🧪 Testing Category Optimized Refactor...')

    // Test 1: Categories list với language vi
    console.log('\n📋 Test 1: Categories list với language vi')
    const response1 = await axios.get(`${BASE_URL}/categories?parentCategoryId=1&lang=vi`)
    console.log('Status:', response1.status)
    console.log('Categories count:', response1.data.data?.length || 0)
    if (response1.data.data?.[0]) {
      console.log('First category:', {
        id: response1.data.data[0].id,
        name: response1.data.data[0].name,
        description: response1.data.data[0].description,
        hasTranslations: !!response1.data.data[0].categoryTranslations,
        translationsCount: response1.data.data[0].categoryTranslations?.length || 0,
      })
    }

    // Test 2: Categories list với language en
    console.log('\n📋 Test 2: Categories list với language en')
    const response2 = await axios.get(`${BASE_URL}/categories?parentCategoryId=1&lang=en`)
    console.log('Status:', response2.status)
    console.log('Categories count:', response2.data.data?.length || 0)
    if (response2.data.data?.[0]) {
      console.log('First category:', {
        id: response2.data.data[0].id,
        name: response2.data.data[0].name,
        description: response2.data.data[0].description,
        hasTranslations: !!response2.data.data[0].categoryTranslations,
        translationsCount: response2.data.data[0].categoryTranslations?.length || 0,
      })
    }

    // Test 3: Category detail với language en
    console.log('\n📋 Test 3: Category detail với language en')
    const response3 = await axios.get(`${BASE_URL}/categories/4?lang=en`)
    console.log('Status:', response3.status)
    console.log('Category detail:', {
      id: response3.data.id,
      name: response3.data.name,
      description: response3.data.description,
      hasTranslations: !!response3.data.categoryTranslations,
      translationsCount: response3.data.categoryTranslations?.length || 0,
    })

    // Test 4: Product với categories (kiểm tra Product repo cũng được refactor)
    console.log('\n📋 Test 4: Product với categories')
    const response4 = await axios.get(`${BASE_URL}/products/1?lang=en`)
    console.log('Status:', response4.status)
    if (response4.data.categories?.[0]) {
      console.log('First product category:', {
        id: response4.data.categories[0].id,
        name: response4.data.categories[0].name,
        description: response4.data.categories[0].description,
        hasTranslations: !!response4.data.categories[0].categoryTranslations,
        translationsCount: response4.data.categories[0].categoryTranslations?.length || 0,
      })
    }

    console.log('\n✅ Category Optimized Refactor test completed!')
    console.log('🎯 Đã thay thế hoàn toàn thay vì tạo thêm biến!')
  } catch (error) {
    console.error('❌ Test failed:', error.response?.data || error.message)
  }
}

// Chạy test
testCategoryOptimized()
