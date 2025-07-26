import { PrismaService } from 'src/shared/services/prisma.service'
import { PrismaClient } from '@prisma/client'
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
  // Additional fields from JSON
  url?: string
  favorite?: number
  sold?: number
  seller_products?: number
  seller_followers?: number
  shop_url?: string
  seller_chats_responded_percentage?: number
  seller_chat_time_reply?: string
  seller_joined_date?: string
  domain?: string
  category_url?: string
  flash_sale?: boolean
  flash_sale_time?: string | null
  vouchers?: any
  gmv_cal?: any
}

interface ProcessedProduct {
  shopeeData: ShopeeProduct
  brandId: string
  categoryId: string
  validImages: string[]
  validVideos: string[]
  variants: Array<{ value: string; options: string[] }> // Giữ nguyên cấu trúc cũ
  specifications: Array<{ name: string; value: string }> // Specifications riêng biệt
  metadata: any // Metadata khác (không bao gồm specifications)
  skus: Array<{
    value: string
    price: number
    stock: number
    image: string
  }>
  reviews: Array<{
    clientName: string
    rating: number
    content: string
    date: string
    likes?: number
    media?: string[]
  }>
}

// New interfaces for user management
interface SellerData {
  sellerId: string
  sellerName: string
  email: string
  password: string
  phoneNumber: string
  avatar: string
  status: 'ACTIVE' | 'INACTIVE' | 'BLOCKED'
  role: 'SELLER'
  shopeeData: {
    rating: number
    products: number
    followers: number
    responseRate: number
    replyTime: string
    joinedDate: string
    shopUrl: string
  }
}

interface CustomerData {
  clientName: string
  email: string
  password: string
  phoneNumber: string
  avatar: string
  status: 'ACTIVE' | 'INACTIVE' | 'BLOCKED'
  role: 'CLIENT'
}

interface AddressData {
  province: string
  district: string
  ward: string
  street: string
  addressType: 'HOME' | 'OFFICE' | 'OTHER'
  recipient?: string
  phoneNumber?: string
}

const DEFAULT_BRAND_NAME = 'No Brand'
const VIETNAMESE_LANGUAGE_ID = 'vi'
const BATCH_SIZE = 1000 // Import all valid products

// Utility functions for user management
function generateVietnamesePhone(): string {
  const prefixes = ['032', '033', '034', '035', '036', '037', '038', '039']
  const prefix = prefixes[Math.floor(Math.random() * prefixes.length)]
  const suffix = Math.floor(Math.random() * 10000000)
    .toString()
    .padStart(7, '0')
  return `+84${prefix}${suffix}`
}

function generateEmail(type: 'seller' | 'client', index: number): string {
  return `${type}${index}.shopsifu.ecommerce@gmail.com`
}

function generatePassword(type: 'seller' | 'client'): string {
  return `${type.charAt(0).toUpperCase() + type.slice(1)}1@@`
}

// Vietnamese addresses for fake data
const VIETNAMESE_ADDRESSES: AddressData[] = [
  {
    province: 'Hà Nội',
    district: 'Cầu Giấy',
    ward: 'Dịch Vọng',
    street: 'Xuân Thủy, 123',
    addressType: 'HOME',
    recipient: 'Nguyễn Văn A',
    phoneNumber: generateVietnamesePhone()
  },
  {
    province: 'TP.HCM',
    district: 'Quận 1',
    ward: 'Bến Nghé',
    street: 'Nguyễn Huệ, 456',
    addressType: 'OFFICE',
    recipient: 'Trần Thị B',
    phoneNumber: generateVietnamesePhone()
  },
  {
    province: 'Đà Nẵng',
    district: 'Hải Châu',
    ward: 'Phước Ninh',
    street: 'Lê Duẩn, 789',
    addressType: 'HOME',
    recipient: 'Lê Văn C',
    phoneNumber: generateVietnamesePhone()
  },
  {
    province: 'Hải Phòng',
    district: 'Hồng Bàng',
    ward: 'Hoàng Văn Thụ',
    street: 'Trần Phú, 321',
    addressType: 'OTHER',
    recipient: 'Phạm Thị D',
    phoneNumber: generateVietnamesePhone()
  },
  {
    province: 'Cần Thơ',
    district: 'Ninh Kiều',
    ward: 'An Hội',
    street: 'Hai Bà Trưng, 654',
    addressType: 'HOME',
    recipient: 'Võ Văn E',
    phoneNumber: generateVietnamesePhone()
  }
]

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
async function batchCreateBrands(brandNames: string[], creatorUserId: string, tx?: any) {
  const prismaClient = tx || prisma
  console.log(`🏷️  Processing ${brandNames.length} unique brands...`)

  const uniqueBrandNames = [...new Set(brandNames.map((name) => name || DEFAULT_BRAND_NAME))]

  // Đường dẫn logo mặc định
  const DEFAULT_BRAND_LOGO =
    'https://shopsifu.s3.ap-southeast-1.amazonaws.com/images/b7de950e-43bd-4f32-b266-d24c080c7a1e.png'

  // Lấy tất cả brands hiện có trong DB (chưa bị xóa)
  const existingBrands = await prismaClient.brand.findMany({
    where: {
      deletedAt: null
    },
    select: { id: true, name: true }
  })

  const existingBrandNames = new Set(existingBrands.map((b) => b.name))
  const seedBrandNames = new Set(uniqueBrandNames)

  // Xóa (soft delete) brands có trong DB nhưng không có trong seed
  const brandsToDelete = existingBrands.filter((b) => !seedBrandNames.has(b.name))
  if (brandsToDelete.length > 0) {
    await prismaClient.brand.updateMany({
      where: {
        id: { in: brandsToDelete.map((b) => b.id) }
      },
      data: {
        deletedAt: new Date()
      }
    })
    console.log(`🗑️  Soft deleted ${brandsToDelete.length} brands không còn trong seed`)
  }

  // Thêm brands mới có trong seed nhưng chưa có trong DB
  const newBrandNames = uniqueBrandNames.filter((name) => !existingBrandNames.has(name))
  if (newBrandNames.length > 0) {
    await prismaClient.brand.createMany({
      data: newBrandNames.map((name) => ({
        name,
        logo: DEFAULT_BRAND_LOGO,
        createdById: creatorUserId
      })),
      skipDuplicates: true
    })
    console.log(`✅ Created ${newBrandNames.length} new brands`)
  }

  // Lấy lại tất cả brands sau khi cập nhật
  const allBrands = await prismaClient.brand.findMany({
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
async function batchCreateCategories(breadcrumbs: string[][], creatorUserId: string, tx?: any) {
  const prismaClient = tx || prisma
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
  const existingCategories = await prismaClient.category.findMany({
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
    await prismaClient.category.createMany({
      data: newParentCategories.map((name) => ({
        name,
        createdById: creatorUserId
      })),
      skipDuplicates: true
    })
    console.log(`✅ Created ${newParentCategories.length} parent categories`)
  }

  // Refresh categories after creating parents
  const updatedCategories = await prismaClient.category.findMany({
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
    await prismaClient.category.createMany({
      data: childCategoriesToCreate.map((cat) => ({
        ...cat,
        createdById: creatorUserId
      })),
      skipDuplicates: true
    })
    console.log(`✅ Created ${childCategoriesToCreate.length} child categories`)
  }

  // Final category map
  const finalCategories = await prismaClient.category.findMany({
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

// Batch create sellers from unique seller_id
async function batchCreateSellers(products: ShopeeProduct[], creatorUserId: string, tx?: any) {
  const prismaClient = tx || prisma
  console.log(`🏪 Processing sellers from ${products.length} products...`)

  // Extract unique sellers
  const uniqueSellers = new Map<string, ShopeeProduct>()
  products.forEach((product) => {
    if (product.seller_id && product.seller_name) {
      uniqueSellers.set(product.seller_id, product)
    }
  })

  console.log(`👥 Found ${uniqueSellers.size} unique sellers`)

  // Get existing sellers in DB
  const existingSellers = await prismaClient.user.findMany({
    where: {
      role: {
        name: 'SELLER'
      },
      deletedAt: null
    },
    select: { id: true, email: true }
  })

  const existingSellerEmails = new Set(existingSellers.map((s) => s.email))
  const sellerMap = new Map<string, string>() // sellerId -> userId

  // Get SELLER role
  const sellerRole = await prismaClient.role.findFirst({
    where: { name: 'SELLER' }
  })

  if (!sellerRole) {
    throw new Error('SELLER role not found in database')
  }

  // Default avatar for sellers
  const DEFAULT_SELLER_AVATAR =
    'https://shopsifu.s3.ap-southeast-1.amazonaws.com/images/b7de950e-43bd-4f32-b266-d24c080c7a1e.png'

  let sellerIndex = 1
  for (const [sellerId, product] of uniqueSellers) {
    const email = generateEmail('seller', sellerIndex)

    // Skip if seller already exists
    if (existingSellerEmails.has(email)) {
      const existingSeller = existingSellers.find((s) => s.email === email)
      if (existingSeller) {
        sellerMap.set(sellerId, existingSeller.id)
      }
      sellerIndex++
      continue
    }

    try {
      const seller = await prismaClient.user.create({
        data: {
          email,
          name: product.seller_name,
          password: generatePassword('seller'),
          phoneNumber: generateVietnamesePhone(),
          avatar: DEFAULT_SELLER_AVATAR,
          status: 'ACTIVE',
          roleId: sellerRole.id,
          createdById: creatorUserId
        },
        select: { id: true, email: true }
      })

      sellerMap.set(sellerId, seller.id)
      console.log(`✅ Created seller: ${product.seller_name} (${email})`)
      sellerIndex++
    } catch (error) {
      console.error(`❌ Failed to create seller ${product.seller_name}:`, error)
    }
  }

  console.log(`📦 Created ${sellerMap.size} sellers`)
  return sellerMap
}

// Batch create clients from unique client_name in reviews
async function batchCreateCustomers(products: ShopeeProduct[], creatorUserId: string, tx?: any) {
  const prismaClient = tx || prisma
  console.log(`👤 Processing clients from product reviews...`)

  // Extract unique clients from reviews
  const uniqueCustomers = new Set<string>()
  products.forEach((product) => {
    if (product.product_ratings) {
      product.product_ratings.forEach((rating) => {
        if (rating.customer_name) {
          uniqueCustomers.add(rating.customer_name)
        }
      })
    }
  })

  console.log(`👥 Found ${uniqueCustomers.size} unique clients`)

  // Get existing clients in DB
  const existingCustomers = await prismaClient.user.findMany({
    where: {
      role: {
        name: 'CLIENT'
      },
      deletedAt: null
    },
    select: { id: true, email: true }
  })

  const existingCustomerEmails = new Set(existingCustomers.map((c) => c.email))
  const clientMap = new Map<string, string>() // clientName -> userId

  // Get CLIENT role
  const clientRole = await prismaClient.role.findFirst({
    where: { name: 'CLIENT' }
  })

  if (!clientRole) {
    throw new Error('CLIENT role not found in database')
  }

  // Default avatar for clients
  const DEFAULT_CLIENT_AVATAR =
    'https://shopsifu.s3.ap-southeast-1.amazonaws.com/images/b7de950e-43bd-4f32-b266-d24c080c7a1e.png'

  let clientIndex = 1
  for (const clientName of uniqueCustomers) {
    const email = generateEmail('client', clientIndex)

    // Skip if client already exists
    if (existingCustomerEmails.has(email)) {
      const existingCustomer = existingCustomers.find((c) => c.email === email)
      if (existingCustomer) {
        clientMap.set(clientName, existingCustomer.id)
      }
      clientIndex++
      continue
    }

    try {
      const client = await prismaClient.user.create({
        data: {
          email,
          name: clientName,
          password: generatePassword('client'),
          phoneNumber: generateVietnamesePhone(),
          avatar: DEFAULT_CLIENT_AVATAR,
          status: 'ACTIVE',
          roleId: clientRole.id,
          createdById: creatorUserId
        },
        select: { id: true, email: true }
      })

      clientMap.set(clientName, client.id)
      console.log(`✅ Created client: ${clientName} (${email})`)
      clientIndex++
    } catch (error) {
      console.error(`❌ Failed to create client ${clientName}:`, error)
    }
  }

  console.log(`📦 Created ${clientMap.size} clients`)
  return clientMap
}

// Batch create addresses for users
async function batchCreateAddresses(users: any[], creatorUserId: string, tx?: any) {
  const prismaClient = tx || prisma
  console.log(`📍 Creating addresses for ${users.length} users...`)

  let addressCount = 0
  let userAddressCount = 0

  for (const user of users) {
    // Create 1-3 addresses per user
    const numAddresses = Math.floor(Math.random() * 3) + 1

    for (let i = 0; i < numAddresses; i++) {
      const addressData = VIETNAMESE_ADDRESSES[Math.floor(Math.random() * VIETNAMESE_ADDRESSES.length)]

      try {
        // Create address
        const address = await prismaClient.address.create({
          data: {
            name: `${addressData.province} - ${addressData.district}`,
            recipient: addressData.recipient,
            phoneNumber: addressData.phoneNumber,
            province: addressData.province,
            district: addressData.district,
            ward: addressData.ward,
            street: addressData.street,
            addressType: addressData.addressType,
            createdById: creatorUserId
          },
          select: { id: true }
        })

        // Create user address relationship
        await prismaClient.userAddress.create({
          data: {
            userId: user.id,
            addressId: address.id,
            isDefault: i === 0 // First address is default
          }
        })

        addressCount++
        userAddressCount++
      } catch (error) {
        console.error(`❌ Failed to create address for user ${user.email}:`, error)
      }
    }
  }

  console.log(`📍 Created ${addressCount} addresses and ${userAddressCount} user-address relationships`)
  return { addressCount, userAddressCount }
}

// Enhanced generate variants with full metadata
function generateEnhancedVariants(
  variations?: Array<{ name: string; variations: string[] }> | null,
  productVariation?: Array<{ name: string; value: string | null }>,
  product?: ShopeeProduct
): Array<{ value: string; options: string[] }> {
  // Giữ nguyên cấu trúc variants như cũ để tương thích với validation schema
  let baseVariants: Array<{ value: string; options: string[] }> = []

  if (!variations || variations.length === 0) {
    baseVariants = [{ value: 'Default', options: ['Default'] }]
  } else {
    variations.forEach((variation) => {
      if (variation.variations && variation.variations.length > 0) {
        baseVariants.push({
          value: variation.name,
          options: variation.variations
        })
      }
    })
    if (baseVariants.length === 0) {
      baseVariants = [{ value: 'Default', options: ['Default'] }]
    }
  }

  return baseVariants
}

// Generate product specifications separately
function generateProductSpecifications(product?: ShopeeProduct): Array<{ name: string; value: string }> {
  if (!product || !product['Product Specifications']) return []
  return product['Product Specifications']
}

// Generate product metadata separately (không bao gồm specifications)
function generateProductMetadata(product?: ShopeeProduct): any {
  if (!product) return null

  return {
    // Shopee metrics
    metrics: {
      shopeeRating: product.rating || 0,
      shopeeReviews: product.reviews || 0,
      shopeeFavorites: product.favorite || 0,
      shopeeSold: product.sold || 0
    },

    // Seller information
    seller: {
      name: product.seller_name || '',
      rating: product.seller_rating || 0,
      totalProducts: product.seller_products || 0,
      followers: product.seller_followers || 0,
      url: product.shop_url || '',
      chatsResponseRate: product.seller_chats_responded_percentage || 0,
      avgReplyTime: product.seller_chat_time_reply || '',
      joinedDate: product.seller_joined_date || null,
      sellerId: product.seller_id || ''
    },

    // Shopee metadata
    shopee: {
      id: product.id || '',
      url: product.url || '',
      categoryId: product.category_id || '',
      currency: product.currency || 'VND',
      domain: product.domain || '',
      categoryUrl: product.category_url || '',
      flashSale: product.flash_sale || false,
      flashSaleTime: product.flash_sale_time || null,
      vouchers: product.vouchers || null,
      gmvCal: product.gmv_cal || null
    }
  }
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

  // Tối ưu hóa phân phối stock và image
  const totalCombinations = combinations.length
  const stockPerSku = Math.max(1, Math.floor(stock / totalCombinations))
  const remainingStock = stock - stockPerSku * totalCombinations

  combinations.forEach((combination, index) => {
    // Phân phối stock đều cho các SKU, phần dư sẽ được cộng vào SKU đầu tiên
    const skuStock = index === 0 ? stockPerSku + remainingStock : stockPerSku

    // Phân phối image theo round-robin để đảm bảo tất cả images được sử dụng
    const imageIndex = index % Math.max(1, images.length)

    skus.push({
      value: combination.join(' - '),
      price: basePrice,
      stock: skuStock,
      image: images[imageIndex] || images[0] || ''
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

      // Process images and videos
      const validImages = product.image.filter((img) => img && img.startsWith('http'))
      const validVideos = product.video?.filter((vid) => vid && vid.startsWith('http')) || []

      // Process reviews
      const reviews = (product.product_ratings || []).map((rating) => ({
        clientName: rating.customer_name,
        rating: rating.rating_stars,
        content: rating.review,
        date: rating.review_date,
        likes: rating.review_likes,
        media: rating.review_media
      }))

      // Generate enhanced variants and SKUs
      const variants = generateEnhancedVariants(product.variations, product.product_variation, product)
      const skus = generateSKUs(variants, product.final_price, product.stock, [...validImages, ...validVideos])

      // Generate specifications and metadata separately
      const specifications = generateProductSpecifications(product)
      const metadata = generateProductMetadata(product)

      processedProducts.push({
        shopeeData: product,
        brandId,
        categoryId,
        validImages,
        validVideos,
        variants,
        specifications,
        metadata,
        skus,
        reviews
      })
    } catch (error) {
      console.error(`❌ Failed to process product: ${product.title}`)
      console.error(`🔍 Error: ${error instanceof Error ? error.message : String(error)}`)
    }
  }

  return processedProducts
}

// Batch create reviews for products
async function batchCreateReviews(
  processedProducts: ProcessedProduct[],
  createdProductsMap: Map<string, string>, // Map<productName, productId>
  clientMap: Map<string, string> // Map<clientName, userId>
): Promise<{ success: number; failed: number }> {
  let successCount = 0
  let failedCount = 0

  console.log(`📝 Creating reviews for products...`)

  // Get or create a default user for reviews (fallback)
  let defaultReviewUser = await prisma.user.findFirst({
    where: {
      role: {
        name: { in: ['CLIENT', 'USER'] }
      }
    }
  })

  if (!defaultReviewUser) {
    // Find any user to use as review author (fallback)
    defaultReviewUser = await prisma.user.findFirst({
      orderBy: { createdAt: 'asc' }
    })
  }

  if (!defaultReviewUser) {
    console.log('❌ No user found for creating reviews')
    return { success: 0, failed: 0 }
  }

  for (const processed of processedProducts) {
    const productId = createdProductsMap.get(processed.shopeeData.title)
    if (!productId || !processed.reviews || processed.reviews.length === 0) {
      continue
    }

    for (const review of processed.reviews) {
      if (!review.content || review.content.trim() === '') {
        continue
      }

      try {
        // Get client user ID from client map, or use default
        const clientUserId = clientMap.get(review.clientName) || defaultReviewUser.id

        // Create a fake order for this review
        const fakePayment = await prisma.payment.create({
          data: {
            status: 'SUCCESS'
          }
        })

        const fakeOrder = await prisma.order.create({
          data: {
            userId: clientUserId,
            status: 'DELIVERED',
            paymentId: fakePayment.id,
            receiver: {
              name: review.clientName || 'Anonymous',
              phone: '0000000000',
              address: 'N/A'
            },
            createdAt: new Date(review.date)
          }
        })

        const reviewData = {
          content: review.content.trim(),
          rating: Math.max(1, Math.min(5, review.rating)), // Ensure rating is 1-5
          productId,
          userId: clientUserId,
          orderId: fakeOrder.id,
          createdAt: new Date(review.date)
        }

        const createdReview = await prisma.review.create({
          data: reviewData
        })

        // Create review media if exists
        if (review.media && review.media.length > 0) {
          for (const mediaUrl of review.media) {
            if (mediaUrl && mediaUrl.startsWith('http')) {
              const isVideo = mediaUrl.includes('.mp4') || mediaUrl.includes('video')
              await prisma.reviewMedia.create({
                data: {
                  url: mediaUrl,
                  type: isVideo ? 'VIDEO' : 'IMAGE',
                  reviewId: createdReview.id
                }
              })
            }
          }
        }

        successCount++
      } catch (error) {
        console.error(`❌ Failed to create review for product: ${processed.shopeeData.title}`)
        console.error(`🔍 Error: ${error instanceof Error ? error.message : String(error)}`)
        failedCount++
      }
    }
  }

  console.log(`✅ Successfully created ${successCount} reviews`)
  console.log(`❌ Failed to create ${failedCount} reviews`)

  return { success: successCount, failed: failedCount }
}
async function batchCreateProducts(
  processedProducts: ProcessedProduct[],
  creatorUserId: string
): Promise<{ success: number; failed: number }> {
  let successCount = 0
  let failedCount = 0

  console.log(`📦 Creating ${processedProducts.length} products in database...`)

  // Process in smaller chunks to avoid transaction timeout
  const chunkSize = 10
  const skuBatchSize = 5000 // Batch size cho SKUs nếu số lượng quá lớn

  // Tối ưu hóa database settings cho bulk operations
  await prisma.$executeRaw`SET work_mem = '16MB'`
  await prisma.$executeRaw`SET maintenance_work_mem = '256MB'`
  await prisma.$executeRaw`SET synchronous_commit = off`

  for (let i = 0; i < processedProducts.length; i += chunkSize) {
    const chunk = processedProducts.slice(i, i + chunkSize)
    const startTime = Date.now()

    try {
      await prisma.$transaction(async (tx) => {
        // Step 1: Create all products first
        const createdProducts: Array<{ id: string; name: string }> = []

        for (const processed of chunk) {
          const { shopeeData, brandId, categoryId, validImages, validVideos, variants, specifications, metadata } =
            processed

          // Combine images and videos
          const allMedia = [...validImages, ...validVideos]

          // Create product with enhanced data
          const product = await tx.product.create({
            data: {
              name: shopeeData.title,
              description: JSON.stringify(metadata), // Store metadata (không bao gồm specifications)
              basePrice: shopeeData.final_price,
              virtualPrice: shopeeData.initial_price,
              brandId,
              images: allMedia, // Include both images and videos
              variants, // Enhanced variants
              specifications, // Store specifications in dedicated field
              createdById: creatorUserId,
              publishedAt: shopeeData.is_available ? new Date() : null,
              categories: {
                connect: { id: categoryId }
              }
            },
            select: { id: true, name: true }
          })

          createdProducts.push(product)
        }

        const productCreationTime = Date.now() - startTime
        console.log(`✅ Created ${createdProducts.length} products in ${productCreationTime}ms`)

        // Step 2: Prepare all SKUs data for bulk insert
        const allSkusData: Array<{
          value: string
          price: number
          stock: number
          image: string
          productId: string
          createdById: string
        }> = []

        for (let j = 0; j < chunk.length; j++) {
          const processed = chunk[j]
          const product = createdProducts[j]

          // Add all SKUs for this product to the bulk array
          processed.skus.forEach((sku) => {
            allSkusData.push({
              ...sku,
              productId: product.id,
              createdById: creatorUserId
            })
          })
        }

        // Step 3: Bulk insert all SKUs in batches if needed
        if (allSkusData.length > 0) {
          const skuStartTime = Date.now()

          if (allSkusData.length <= skuBatchSize) {
            // Insert tất cả SKUs trong một lần
            await tx.sKU.createMany({
              data: allSkusData,
              skipDuplicates: true
            })
            const skuTime = Date.now() - skuStartTime
            console.log(
              `✅ Bulk inserted ${allSkusData.length} SKUs in ${skuTime}ms (${Math.round((allSkusData.length / skuTime) * 1000)} SKUs/sec)`
            )
          } else {
            // Chia nhỏ SKUs thành các batch nhỏ hơn
            let skuInsertedCount = 0
            for (let k = 0; k < allSkusData.length; k += skuBatchSize) {
              const skuBatch = allSkusData.slice(k, k + skuBatchSize)
              const batchStartTime = Date.now()

              await tx.sKU.createMany({
                data: skuBatch,
                skipDuplicates: true
              })

              const batchTime = Date.now() - batchStartTime
              skuInsertedCount += skuBatch.length
              console.log(
                `✅ Bulk inserted SKU batch ${Math.floor(k / skuBatchSize) + 1}: ${skuBatch.length} SKUs in ${batchTime}ms`
              )
            }

            const totalSkuTime = Date.now() - skuStartTime
            console.log(
              `✅ Total SKUs inserted: ${skuInsertedCount} in ${totalSkuTime}ms (${Math.round((skuInsertedCount / totalSkuTime) * 1000)} SKUs/sec)`
            )
          }
        }

        // Step 4: Create all product translations
        const allTranslationsData: Array<{
          productId: string
          languageId: string
          name: string
          description: string
          createdById: string
        }> = []

        for (let j = 0; j < chunk.length; j++) {
          const processed = chunk[j]
          const product = createdProducts[j]

          allTranslationsData.push({
            productId: product.id,
            languageId: VIETNAMESE_LANGUAGE_ID,
            name: processed.shopeeData.title,
            description: JSON.stringify(processed.metadata), // Store metadata (không bao gồm specifications)
            createdById: creatorUserId
          })
        }

        // Step 5: Bulk insert all translations
        if (allTranslationsData.length > 0) {
          const translationStartTime = Date.now()

          await tx.productTranslation.createMany({
            data: allTranslationsData,
            skipDuplicates: true
          })

          const translationTime = Date.now() - translationStartTime
          console.log(`✅ Bulk inserted ${allTranslationsData.length} product translations in ${translationTime}ms`)
        }

        const totalTime = Date.now() - startTime
        console.log(`⏱️  Total chunk processing time: ${totalTime}ms`)

        successCount += chunk.length
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

  // Reset database settings
  await prisma.$executeRaw`SET work_mem = '4MB'`
  await prisma.$executeRaw`SET maintenance_work_mem = '64MB'`
  await prisma.$executeRaw`SET synchronous_commit = on`

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

    // Get existing products in DB
    const existingProducts = await prisma.product.findMany({
      where: {
        deletedAt: null
      },
      select: { id: true, name: true }
    })

    console.log(`🔄 Products currently in DB: ${existingProducts.length}`)

    // Create maps for comparison
    const validProductNames = new Set(validProducts.map((p) => p.title))
    const existingProductNames = new Set(existingProducts.map((p) => p.name))

    // Find products to delete (in DB but not in JSON)
    const productsToDelete = existingProducts.filter((p) => !validProductNames.has(p.name))

    // Find products to add (in JSON but not in DB)
    const productsToAdd = validProducts.filter((p) => !existingProductNames.has(p.title))

    console.log(`🗑️  Products to delete (not in JSON): ${productsToDelete.length}`)
    console.log(`📥 Products to add (new from JSON): ${productsToAdd.length}`)

    // Step 1: Delete products not in JSON
    if (productsToDelete.length > 0) {
      console.log('🗑️  Hard deleting products not in JSON...')
      const deleteResult = await prisma.product.deleteMany({
        where: {
          id: {
            in: productsToDelete.map((p) => p.id)
          }
        }
      })
      console.log(`✅ Hard deleted ${deleteResult.count} products`)
    }

    // Step 2: Add new products from JSON
    if (productsToAdd.length === 0) {
      console.log('✅ No new products to add!')
      return
    }

    // Limit to batch size for processing
    const productsToImport = productsToAdd.slice(0, BATCH_SIZE)
    console.log(`🎯 Importing ${productsToImport.length} products (batch size: ${BATCH_SIZE})`)

    // Step 3 & 4: Batch create brands & categories trong transaction
    let brandMap: Map<string, string>
    let categoryMap: Map<string, string>
    let sellerMap: Map<string, string>
    let clientMap: Map<string, string>

    await prisma.$transaction(async (tx) => {
      brandMap = await batchCreateBrands(
        productsToImport.map((p) => p.brand || DEFAULT_BRAND_NAME),
        creatorUser.id,
        tx
      )
      categoryMap = await batchCreateCategories(
        productsToImport.map((p) => p.breadcrumb),
        creatorUser.id,
        tx
      )
    })

    // Step 5: Create sellers and clients
    console.log('\n👥 Creating sellers and clients...')
    sellerMap = await batchCreateSellers(productsToImport, creatorUser.id)
    clientMap = await batchCreateCustomers(productsToImport, creatorUser.id)

    // Step 6: Create addresses for all users
    console.log('\n📍 Creating addresses for users...')
    const allUsers = await prisma.user.findMany({
      where: {
        deletedAt: null
      },
      select: { id: true, email: true }
    })
    const addressResult = await batchCreateAddresses(allUsers, creatorUser.id)

    // Step 7: Process products
    console.log('🔄 Processing products...')
    const processedProducts = await processProductsBatch(productsToImport, brandMap!, categoryMap!)
    console.log(`✅ Successfully processed: ${processedProducts.length}/${productsToImport.length} products`)

    // Step 8: Batch create products
    const result = await batchCreateProducts(processedProducts, creatorUser.id)

    // Step 9: Create reviews if products were successfully created
    let reviewResult = { success: 0, failed: 0 }
    if (result.success > 0) {
      console.log('\n📝 Creating product reviews...')

      // Get created products map
      const createdProducts = await prisma.product.findMany({
        where: {
          name: { in: processedProducts.map((p) => p.shopeeData.title) },
          deletedAt: null
        },
        select: { id: true, name: true }
      })

      const productNameToIdMap = new Map<string, string>()
      createdProducts.forEach((product) => {
        productNameToIdMap.set(product.name, product.id)
      })

      reviewResult = await batchCreateReviews(processedProducts, productNameToIdMap, clientMap!)
    }

    // Summary
    console.log('\n🎉 Import Summary:')
    console.log(`📊 Total products in JSON: ${shopeeProducts.length}`)
    console.log(`✅ Valid products: ${validProducts.length}`)
    console.log(`❌ Invalid products: ${invalidProducts.length}`)
    console.log(`🔄 Products previously in DB: ${existingProducts.length}`)
    console.log(`🗑️  Products deleted (not in JSON): ${productsToDelete.length}`)
    console.log(`📥 Products added (new from JSON): ${productsToAdd.length}`)
    console.log(`🎯 Attempted import: ${productsToImport.length}`)
    console.log(`✅ Successfully imported: ${result.success}`)
    console.log(`❌ Failed to import: ${result.failed}`)
    console.log(`📝 Reviews created: ${reviewResult.success}`)
    console.log(`❌ Reviews failed: ${reviewResult.failed}`)
    console.log(`🏷️  Brands created/used: ${brandMap!.size}`)
    console.log(`📁 Categories created/used: ${categoryMap!.size}`)
    console.log(`🏪 Sellers created: ${sellerMap!.size}`)
    console.log(`👤 Customers created: ${clientMap!.size}`)
    console.log(`📍 Addresses created: ${addressResult.addressCount}`)
    console.log(`🔗 User-address relationships: ${addressResult.userAddressCount}`)

    if (result.success > 0) {
      console.log('\n✅ Import completed successfully!')
      console.log(`📊 Enhanced data imported:`)
      console.log(`   🎬 Videos: ${processedProducts.reduce((sum, p) => sum + p.validVideos.length, 0)}`)
      console.log(`   📋 Product specs: ${processedProducts.reduce((sum, p) => sum + p.specifications.length, 0)}`)
      console.log(`   🏪 Seller info: ${processedProducts.filter((p) => p.shopeeData.seller_name).length}`)
      console.log(`   📊 Metrics: ${processedProducts.filter((p) => p.shopeeData.rating > 0).length}`)
      console.log(`   📝 Reviews: ${reviewResult.success}`)
      console.log(`   👥 Real sellers: ${sellerMap!.size}`)
      console.log(`   👤 Real clients: ${clientMap!.size}`)
      console.log(`   📍 User addresses: ${addressResult.addressCount}`)

      if (productsToAdd.length > BATCH_SIZE) {
        console.log(`💡 To import all ${productsToAdd.length} new products, increase BATCH_SIZE in the script`)
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
