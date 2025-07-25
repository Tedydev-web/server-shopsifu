import { PrismaService } from 'src/shared/services/prisma.service'
import * as fs from 'fs'
import * as path from 'path'

const prisma = new PrismaService()

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
    customer_name: string
    rating_stars: number
    review: string
    review_date: string
    review_likes?: number
    review_media?: string[]
  }>
  is_available: boolean
}

interface ProcessedProduct {
  shopeeData: ShopeeProduct
  brandId: string
  categoryId: string
  validImages: string[]
  variants: Array<{ value: string; options: string[] }>
  skus: Array<{
    value: string
    price: number
    stock: number
    image: string
  }>
}

const DEFAULT_BRAND_NAME = 'No Brand'
const VIETNAMESE_LANGUAGE_ID = 'vi'
const BATCH_SIZE = 826 // Import all valid products

// Validation function với logic giống analyze script
function validateProduct(product: ShopeeProduct): { isValid: boolean; reason?: string } {
  if (!product.id) return { isValid: false, reason: 'Missing ID' }
  if (!product.title || product.title.trim() === '') return { isValid: false, reason: 'Missing title' }
  if (!product.final_price || product.final_price <= 0) return { isValid: false, reason: 'Invalid price' }
  if (product.stock === undefined || product.stock === null || product.stock < 0)
    return { isValid: false, reason: 'Invalid stock' }
  if (!product.breadcrumb || product.breadcrumb.length < 2) return { isValid: false, reason: 'Invalid breadcrumb' }
  if (!product.image || product.image.length === 0) return { isValid: false, reason: 'No images' }

  const validImages = product.image.filter((img) => img && img.startsWith('http'))
  if (validImages.length === 0) return { isValid: false, reason: 'No valid images' }

  return { isValid: true }
}

// Batch create brands
async function batchCreateBrands(brandNames: string[], creatorUserId: string) {
  console.log(`🏷️  Processing ${brandNames.length} unique brands...`)

  const uniqueBrandNames = [...new Set(brandNames.map((name) => name || DEFAULT_BRAND_NAME))]

  // Kiểm tra brands đã tồn tại
  const existingBrands = await prisma.brand.findMany({
    where: {
      name: { in: uniqueBrandNames },
      deletedAt: null
    },
    select: { id: true, name: true }
  })

  const existingBrandNames = new Set(existingBrands.map((b) => b.name))
  const newBrandNames = uniqueBrandNames.filter((name) => !existingBrandNames.has(name))

  // Tạo brands mới
  if (newBrandNames.length > 0) {
    await prisma.brand.createMany({
      data: newBrandNames.map((name) => ({
        name,
        logo: 'https://shopsifu.s3.ap-southeast-1.amazonaws.com/images/b7de950e-43bd-4f32-b266-d24c080c7a1e.png',
        createdById: creatorUserId
      })),
      skipDuplicates: true
    })
    console.log(`✅ Created ${newBrandNames.length} new brands`)
  }

  // Lấy tất cả brands sau khi tạo
  const allBrands = await prisma.brand.findMany({
    where: {
      name: { in: uniqueBrandNames },
      deletedAt: null
    },
    select: { id: true, name: true }
  })

  // Tạo map để lookup nhanh
  const brandMap = new Map<string, string>()
  allBrands.forEach((brand) => {
    brandMap.set(brand.name, brand.id)
  })

  console.log(`📦 Loaded ${allBrands.length} brands into cache`)
  return brandMap
}

// Batch create categories (2-level only)
async function batchCreateCategories(breadcrumbs: string[][], creatorUserId: string) {
  console.log(`📁 Processing categories from ${breadcrumbs.length} products...`)

  const categorySet = new Set<string>()
  const parentChildPairs = new Set<string>()

  // Collect unique categories (2-level max)
  breadcrumbs.forEach((breadcrumb) => {
    const categoryNames = breadcrumb.slice(1, -1).slice(0, 2) // Max 2 levels
    if (categoryNames.length > 0) {
      categorySet.add(categoryNames[0]) // Parent
      if (categoryNames.length > 1) {
        categorySet.add(categoryNames[1]) // Child
        parentChildPairs.add(`${categoryNames[0]}|${categoryNames[1]}`)
      }
    }
  })

  if (categorySet.size === 0) {
    categorySet.add('Khác') // Default category
  }

  const uniqueCategoryNames = [...categorySet]

  // Get existing categories
  const existingCategories = await prisma.category.findMany({
    where: {
      name: { in: uniqueCategoryNames },
      deletedAt: null
    },
    select: { id: true, name: true, parentCategoryId: true }
  })

  const existingCategoryMap = new Map<string, { id: string; parentCategoryId: string | null }>()
  existingCategories.forEach((cat) => {
    existingCategoryMap.set(cat.name, { id: cat.id, parentCategoryId: cat.parentCategoryId })
  })

  // Create missing parent categories first
  const existingCategoryNames = new Set(existingCategories.map((c) => c.name))
  const parentCategories = [...categorySet].filter(
    (name) => ![...parentChildPairs].some((pair) => pair.split('|')[1] === name)
  )
  const newParentCategories = parentCategories.filter((name) => !existingCategoryNames.has(name))

  if (newParentCategories.length > 0) {
    await prisma.category.createMany({
      data: newParentCategories.map((name) => ({
        name,
        createdById: creatorUserId
      })),
      skipDuplicates: true
    })
    console.log(`✅ Created ${newParentCategories.length} parent categories`)
  }

  // Refresh categories after creating parents
  const updatedCategories = await prisma.category.findMany({
    where: {
      name: { in: uniqueCategoryNames },
      deletedAt: null
    },
    select: { id: true, name: true, parentCategoryId: true }
  })

  updatedCategories.forEach((cat) => {
    existingCategoryMap.set(cat.name, { id: cat.id, parentCategoryId: cat.parentCategoryId })
  })

  // Create child categories
  const childCategoriesToCreate: Array<{ name: string; parentCategoryId: string }> = []

  for (const pair of parentChildPairs) {
    const [parentName, childName] = pair.split('|')
    const parentCategory = existingCategoryMap.get(parentName)
    const childCategory = existingCategoryMap.get(childName)

    if (parentCategory && !childCategory) {
      childCategoriesToCreate.push({
        name: childName,
        parentCategoryId: parentCategory.id
      })
    }
  }

  if (childCategoriesToCreate.length > 0) {
    await prisma.category.createMany({
      data: childCategoriesToCreate.map((cat) => ({
        ...cat,
        createdById: creatorUserId
      })),
      skipDuplicates: true
    })
    console.log(`✅ Created ${childCategoriesToCreate.length} child categories`)
  }

  // Final category map
  const finalCategories = await prisma.category.findMany({
    where: {
      name: { in: uniqueCategoryNames },
      deletedAt: null
    },
    select: { id: true, name: true, parentCategoryId: true }
  })

  const categoryMap = new Map<string, string>()
  finalCategories.forEach((cat) => {
    categoryMap.set(cat.name, cat.id)
  })

  console.log(`📦 Loaded ${finalCategories.length} categories into cache`)
  return categoryMap
}

// Generate variants from Shopee data
function generateVariants(
  variations?: Array<{ name: string; variations: string[] }> | null,
  productVariation?: Array<{ name: string; value: string | null }>
): Array<{ value: string; options: string[] }> {
  if (!variations || variations.length === 0) {
    return [{ value: 'Default', options: ['Default'] }]
  }

  const variants: Array<{ value: string; options: string[] }> = []

  variations.forEach((variation) => {
    if (variation.variations && variation.variations.length > 0) {
      variants.push({
        value: variation.name,
        options: variation.variations
      })
    }
  })

  return variants.length > 0 ? variants : [{ value: 'Default', options: ['Default'] }]
}

// Generate SKUs from variants
function generateSKUs(
  variants: Array<{ value: string; options: string[] }>,
  basePrice: number,
  stock: number,
  images: string[]
): Array<{ value: string; price: number; stock: number; image: string }> {
  const skus: Array<{ value: string; price: number; stock: number; image: string }> = []

  if (variants.length === 0 || variants[0].value === 'Default') {
    return [
      {
        value: 'Default',
        price: basePrice,
        stock: stock,
        image: images[0] || ''
      }
    ]
  }

  // Create cartesian product
  function cartesianProduct(arrays: string[][]): string[][] {
    if (arrays.length === 0) return [[]]
    if (arrays.length === 1) return arrays[0].map((x) => [x])

    const result: string[][] = []
    const restProduct = cartesianProduct(arrays.slice(1))

    for (const item of arrays[0]) {
      for (const restItem of restProduct) {
        result.push([item, ...restItem])
      }
    }

    return result
  }

  const variantOptions = variants.map((v) => v.options)
  const combinations = cartesianProduct(variantOptions)

  combinations.forEach((combination, index) => {
    skus.push({
      value: combination.join(' - '),
      price: basePrice,
      stock: Math.floor(stock / combinations.length),
      image: images[index % images.length] || images[0] || ''
    })
  })

  return skus
}

// Process products in batches
async function processProductsBatch(
  products: ShopeeProduct[],
  brandMap: Map<string, string>,
  categoryMap: Map<string, string>
): Promise<ProcessedProduct[]> {
  const processedProducts: ProcessedProduct[] = []

  for (const product of products) {
    try {
      // Get brand ID
      const brandName = product.brand || DEFAULT_BRAND_NAME
      const brandId = brandMap.get(brandName)
      if (!brandId) {
        throw new Error(`Brand not found: ${brandName}`)
      }

      // Get category ID (2-level max)
      const categoryNames = product.breadcrumb.slice(1, -1).slice(0, 2)
      let categoryId: string

      if (categoryNames.length === 0) {
        categoryId = categoryMap.get('Khác')!
      } else if (categoryNames.length === 1) {
        categoryId = categoryMap.get(categoryNames[0])!
      } else {
        // Try child category first, fallback to parent
        categoryId = categoryMap.get(categoryNames[1]) || categoryMap.get(categoryNames[0])!
      }

      if (!categoryId) {
        throw new Error(`Category not found for: ${categoryNames.join(' > ')}`)
      }

      // Process images
      const validImages = product.image.filter((img) => img && img.startsWith('http'))

      // Generate variants and SKUs
      const variants = generateVariants(product.variations, product.product_variation)
      const skus = generateSKUs(variants, product.final_price, product.stock, validImages)

      processedProducts.push({
        shopeeData: product,
        brandId,
        categoryId,
        validImages,
        variants,
        skus
      })
    } catch (error) {
      console.error(`❌ Failed to process product: ${product.title}`)
      console.error(`🔍 Error: ${error instanceof Error ? error.message : String(error)}`)
    }
  }

  return processedProducts
}

// Batch create products in transaction
async function batchCreateProducts(
  processedProducts: ProcessedProduct[],
  creatorUserId: string
): Promise<{ success: number; failed: number }> {
  let successCount = 0
  let failedCount = 0

  console.log(`📦 Creating ${processedProducts.length} products in database...`)

  // Process in smaller chunks to avoid transaction timeout
  const chunkSize = 10
  for (let i = 0; i < processedProducts.length; i += chunkSize) {
    const chunk = processedProducts.slice(i, i + chunkSize)

    try {
      await prisma.$transaction(async (tx) => {
        for (const processed of chunk) {
          const { shopeeData, brandId, categoryId, validImages, variants, skus } = processed

          // Create product
          const product = await tx.product.create({
            data: {
              name: shopeeData.title,
              description: shopeeData['Product Description'] || '',
              basePrice: shopeeData.final_price,
              virtualPrice: shopeeData.initial_price,
              brandId,
              images: validImages,
              variants,
              createdById: creatorUserId,
              publishedAt: shopeeData.is_available ? new Date() : null,
              categories: {
                connect: { id: categoryId }
              }
            }
          })

          // Create SKUs
          await tx.sKU.createMany({
            data: skus.map((sku) => ({
              ...sku,
              productId: product.id,
              createdById: creatorUserId
            }))
          })

          // Create translation
          await tx.productTranslation.create({
            data: {
              productId: product.id,
              languageId: VIETNAMESE_LANGUAGE_ID,
              name: shopeeData.title,
              description: shopeeData['Product Description'] || '',
              createdById: creatorUserId
            }
          })

          successCount++
        }
      })

      if (i % 50 === 0) {
        console.log(
          `✅ Progress: ${Math.min(i + chunkSize, processedProducts.length)}/${processedProducts.length} products`
        )
      }
    } catch (error) {
      failedCount += chunk.length
      console.error(`❌ Failed to create chunk ${i}-${i + chunkSize}:`)
      console.error(`🔍 Error: ${error instanceof Error ? error.message : String(error)}`)
    }
  }

  return { success: successCount, failed: failedCount }
}

// Ensure language exists
async function ensureLanguageExists() {
  let language = await prisma.language.findUnique({
    where: { id: VIETNAMESE_LANGUAGE_ID }
  })

  if (!language) {
    let creatorUser = await prisma.user.findFirst({
      where: {
        role: {
          name: { in: ['Admin', 'Seller'] }
        }
      }
    })

    if (!creatorUser) {
      creatorUser = await prisma.user.findFirst({
        orderBy: { createdAt: 'asc' }
      })
    }

    if (!creatorUser) {
      throw new Error('No user found in database. Please create at least one user first.')
    }

    language = await prisma.language.create({
      data: {
        id: VIETNAMESE_LANGUAGE_ID,
        name: 'Tiếng Việt',
        createdById: creatorUser.id
      }
    })
  }

  return language
}

// Main import function
async function importProductsOptimized() {
  try {
    console.log('🚀 Starting optimized product import...')
    console.log(`⚙️  Batch size: ${BATCH_SIZE} products`)

    // Ensure language exists
    await ensureLanguageExists()

    // Find creator user
    let creatorUser = await prisma.user.findFirst({
      where: {
        role: {
          name: { in: ['Admin', 'Seller'] }
        }
      }
    })

    if (!creatorUser) {
      creatorUser = await prisma.user.findFirst({
        orderBy: { createdAt: 'asc' }
      })
    }

    if (!creatorUser) {
      throw new Error('No user found in database. Please create at least one user first.')
    }

    console.log(`👤 Using creator: ${creatorUser.name} (ID: ${creatorUser.id})`)

    // Read JSON data
    const jsonPath = path.join(process.cwd(), 'initialScript', 'product', 'data', 'Shopee-products.json')
    const jsonData = fs.readFileSync(jsonPath, 'utf-8')
    const shopeeProducts: ShopeeProduct[] = JSON.parse(jsonData)

    console.log(`📦 Total products in JSON: ${shopeeProducts.length}`)

    // Validate products
    const validProducts: ShopeeProduct[] = []
    const invalidProducts: Array<{ product: ShopeeProduct; reason: string }> = []
    const validationStats = {
      missingId: 0,
      missingTitle: 0,
      invalidPrice: 0,
      invalidStock: 0,
      invalidBreadcrumb: 0,
      noImages: 0,
      noValidImages: 0
    }

    for (const product of shopeeProducts) {
      const validation = validateProduct(product)
      if (validation.isValid) {
        validProducts.push(product)
      } else {
        invalidProducts.push({ product, reason: validation.reason! })
        const reason = validation.reason!
        if (reason === 'Missing ID') validationStats.missingId++
        else if (reason === 'Missing title') validationStats.missingTitle++
        else if (reason === 'Invalid price') validationStats.invalidPrice++
        else if (reason === 'Invalid stock') validationStats.invalidStock++
        else if (reason === 'Invalid breadcrumb') validationStats.invalidBreadcrumb++
        else if (reason === 'No images') validationStats.noImages++
        else if (reason === 'No valid images') validationStats.noValidImages++
      }
    }

    console.log(`✅ Valid products: ${validProducts.length}`)
    console.log(`❌ Invalid products: ${invalidProducts.length}`)
    console.log('📊 Validation breakdown:', validationStats)

    if (validProducts.length === 0) {
      console.log('❌ No valid products to import!')
      return
    }

    // Check existing products
    const existingProducts = await prisma.product.findMany({
      where: {
        name: { in: validProducts.map((p) => p.title) },
        deletedAt: null
      },
      select: { name: true }
    })

    const existingProductNames = new Set(existingProducts.map((p) => p.name))
    const newProducts = validProducts.filter((p) => !existingProductNames.has(p.title))

    console.log(`🔄 Products already in DB: ${existingProducts.length}`)
    console.log(`📥 New products to import: ${newProducts.length}`)

    if (newProducts.length === 0) {
      console.log('✅ All valid products already imported!')
      return
    }

    // Limit to batch size for testing
    const productsToImport = newProducts.slice(0, BATCH_SIZE)
    console.log(`🎯 Importing ${productsToImport.length} products (batch size: ${BATCH_SIZE})`)

    // Step 1: Batch create brands
    const brandNames = productsToImport.map((p) => p.brand || DEFAULT_BRAND_NAME)
    const brandMap = await batchCreateBrands(brandNames, creatorUser.id)

    // Step 2: Batch create categories
    const breadcrumbs = productsToImport.map((p) => p.breadcrumb)
    const categoryMap = await batchCreateCategories(breadcrumbs, creatorUser.id)

    // Step 3: Process products
    console.log('🔄 Processing products...')
    const processedProducts = await processProductsBatch(productsToImport, brandMap, categoryMap)
    console.log(`✅ Successfully processed: ${processedProducts.length}/${productsToImport.length} products`)

    // Step 4: Batch create products
    const result = await batchCreateProducts(processedProducts, creatorUser.id)

    // Summary
    console.log('\n🎉 Import Summary:')
    console.log(`📊 Total products in JSON: ${shopeeProducts.length}`)
    console.log(`✅ Valid products: ${validProducts.length}`)
    console.log(`❌ Invalid products: ${invalidProducts.length}`)
    console.log(`🔄 Already in DB: ${existingProducts.length}`)
    console.log(`📥 Attempted import: ${productsToImport.length}`)
    console.log(`✅ Successfully imported: ${result.success}`)
    console.log(`❌ Failed to import: ${result.failed}`)
    console.log(`🏷️  Brands created/used: ${brandMap.size}`)
    console.log(`📁 Categories created/used: ${categoryMap.size}`)

    if (result.success > 0) {
      console.log('\n✅ Import completed successfully!')
      if (newProducts.length > BATCH_SIZE) {
        console.log(`💡 To import all ${newProducts.length} products, increase BATCH_SIZE in the script`)
      }
    }
  } catch (error) {
    console.error('❌ Fatal error during optimized import:', error)
    throw error
  } finally {
    await prisma.$disconnect()
  }
}

// Export for use as module
export { importProductsOptimized }

// Run if called directly
if (require.main === module) {
  importProductsOptimized()
    .then(() => {
      console.log('🎯 Optimized import completed!')
      process.exit(0)
    })
    .catch((error) => {
      console.error('💥 Optimized import failed:', error)
      process.exit(1)
    })
}
