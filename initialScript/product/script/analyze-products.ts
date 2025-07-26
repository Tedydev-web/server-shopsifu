import * as fs from 'fs'
import * as path from 'path'

interface ShopeeProduct {
  id: string
  title: string
  rating: number
  reviews: number
  initial_price: number
  final_price: number
  currency: string
  stock: number
  image: string[]
  video?: string[]
  seller_name: string
  seller_id: string
  breadcrumb: string[]
  'Product Specifications'?: Array<{ name: string; value: string }>
  'Product Description': string
  seller_rating: number
  brand?: string
  category_id: string
  variations?: Array<{ name: string; variations: string[] }> | null
  product_variation?: Array<{ name: string; value: string | null }>
  product_ratings?: Array<{
    client_name: string
    rating_stars: number
    review: string
    review_date: string
    review_likes?: number
    review_media?: string[]
  }>
  is_available: boolean
}

function analyzeData() {
  console.log('📊 Analyzing Shopee products data...\n')

  const jsonPath = path.join(__dirname, 'product', 'data', 'Shopee-products.json')
  const jsonData = fs.readFileSync(jsonPath, 'utf-8')
  const products: ShopeeProduct[] = JSON.parse(jsonData)

  console.log(`📦 Total products: ${products.length}`)

  // Phân tích brands
  const brands = new Set<string>()
  products.forEach((p) => {
    if (p.brand) brands.add(p.brand)
  })
  console.log(`🏷️  Unique brands: ${brands.size}`)
  console.log(`🏷️  Products without brand: ${products.filter((p) => !p.brand).length}`)

  // Phân tích categories
  const categories = new Set<string>()
  products.forEach((p) => {
    p.breadcrumb.slice(1, -1).forEach((cat) => categories.add(cat))
  })
  console.log(`📁 Unique categories: ${categories.size}`)

  // Phân tích variations
  const productsWithVariations = products.filter((p) => p.variations && p.variations.length > 0)
  console.log(`🔄 Products with variations: ${productsWithVariations.length}`)

  // Phân tích reviews
  const productsWithReviews = products.filter((p) => p.product_ratings && p.product_ratings.length > 0)
  const totalReviews = products.reduce((sum, p) => sum + (p.product_ratings?.length || 0), 0)
  console.log(`⭐ Products with reviews: ${productsWithReviews.length}`)
  console.log(`⭐ Total reviews: ${totalReviews}`)

  // Phân tích giá
  const prices = products.map((p) => p.final_price).filter((p) => p > 0)
  const avgPrice = prices.reduce((sum, p) => sum + p, 0) / prices.length
  const minPrice = Math.min(...prices)
  const maxPrice = Math.max(...prices)
  console.log(`💰 Price range: ${minPrice.toLocaleString()} - ${maxPrice.toLocaleString()} VND`)
  console.log(`💰 Average price: ${avgPrice.toLocaleString()} VND`)

  // Phân tích availability
  const availableProducts = products.filter((p) => p.is_available)
  console.log(`✅ Available products: ${availableProducts.length}`)

  // Top categories
  console.log('\n📁 Top 10 Categories:')
  const categoryCounts = new Map<string, number>()
  products.forEach((p) => {
    p.breadcrumb.slice(1, -1).forEach((cat) => {
      categoryCounts.set(cat, (categoryCounts.get(cat) || 0) + 1)
    })
  })

  Array.from(categoryCounts.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .forEach(([cat, count]) => {
      console.log(`  ${cat}: ${count} products`)
    })

  // Top brands
  console.log('\n🏷️  Top 10 Brands:')
  const brandCounts = new Map<string, number>()
  products.forEach((p) => {
    if (p.brand) {
      brandCounts.set(p.brand, (brandCounts.get(p.brand) || 0) + 1)
    }
  })

  Array.from(brandCounts.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .forEach(([brand, count]) => {
      console.log(`  ${brand}: ${count} products`)
    })

  // Sample product structure
  console.log('\n📋 Sample product structure:')
  const sampleProduct = products[0]
  console.log(
    JSON.stringify(
      {
        id: sampleProduct.id,
        title: sampleProduct.title,
        price: sampleProduct.final_price,
        brand: sampleProduct.brand,
        category: sampleProduct.breadcrumb.slice(1, -1),
        hasVariations: !!(sampleProduct.variations && sampleProduct.variations.length > 0),
        hasReviews: !!(sampleProduct.product_ratings && sampleProduct.product_ratings.length > 0),
        stock: sampleProduct.stock,
        isAvailable: sampleProduct.is_available
      },
      null,
      2
    )
  )
}

function validateData() {
  console.log('🔍 Validating data integrity...\n')

  const jsonPath = path.join(__dirname, 'product', 'data', 'Shopee-products.json')
  const jsonData = fs.readFileSync(jsonPath, 'utf-8')
  const products: ShopeeProduct[] = JSON.parse(jsonData)

  let validProducts = 0
  let issues = 0

  const validationIssues: string[] = []

  products.forEach((product, index) => {
    const productIssues: string[] = []

    // Kiểm tra các field bắt buộc
    if (!product.id) productIssues.push('Missing ID')
    if (!product.title || product.title.trim() === '') productIssues.push('Missing title')
    if (!product.final_price || product.final_price <= 0) productIssues.push('Invalid price')
    if (!product.stock || product.stock < 0) productIssues.push('Invalid stock')
    if (!product.breadcrumb || product.breadcrumb.length < 2) productIssues.push('Invalid breadcrumb')

    // Kiểm tra images
    if (!product.image || product.image.length === 0) {
      productIssues.push('No images')
    } else {
      const validImages = product.image.filter((img) => img && img.startsWith('http'))
      if (validImages.length === 0) productIssues.push('No valid images')
    }

    if (productIssues.length > 0) {
      issues++
      validationIssues.push(`Product ${index + 1} (${product.title}): ${productIssues.join(', ')}`)
    } else {
      validProducts++
    }
  })

  console.log(`✅ Valid products: ${validProducts}`)
  console.log(`❌ Products with issues: ${issues}`)

  if (validationIssues.length > 0) {
    console.log('\n🚨 Validation Issues (first 10):')
    validationIssues.slice(0, 10).forEach((issue) => console.log(`  ${issue}`))

    if (validationIssues.length > 10) {
      console.log(`  ... and ${validationIssues.length - 10} more issues`)
    }
  }

  return { validProducts, issues }
}

// Chạy phân tích
if (require.main === module) {
  analyzeData()
  console.log('\n' + '='.repeat(50))
  validateData()
}

export { analyzeData, validateData }
