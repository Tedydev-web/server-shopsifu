/**
 * Test Category Flattened Response
 *
 * Kiểm tra Category API với flattened response đã được refactor:
 * - GET /categories?parentCategoryId=1&lang=en
 * - GET /categories?parentCategoryId=1&lang=vi
 * - Response format: { data: [{ id, name, description, ... }] } (không có categoryTranslations array)
 */

import axios from 'axios'

const BASE_URL = 'http://localhost:3000'

async function testCategoryFlattened() {
  try {
    console.log('🧪 Testing Category Flattened Response...')

    // Test 1: Categories với language vi
    console.log('\n📋 Test 1: Categories với language vi')
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

    // Test 2: Categories với language en
    console.log('\n📋 Test 2: Categories với language en')
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

    console.log('\n✅ Category Flattened Response test completed!')
  } catch (error) {
    console.error('❌ Test failed:', error.response?.data || error.message)
  }
}

// Chạy test
testCategoryFlattened()
