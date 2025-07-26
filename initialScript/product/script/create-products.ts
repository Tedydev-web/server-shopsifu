import { PrismaClient } from '@prisma/client'
import * as fs from 'fs'
import * as path from 'path'
import { HashingService } from 'src/shared/services/hashing.service'

// COPY operations for optimized bulk inserts
async function copyUsers(
  users: Array<{
    email: string
    name: string
    password: string
    phoneNumber: string
    avatar: string
    status: 'ACTIVE' | 'INACTIVE' | 'BLOCKED'
    roleId: string
    createdById: string
    createdAt: Date
    updatedAt: Date
  }>,
  tx: PrismaClient
): Promise<void> {
  if (users.length === 0) return

  // Sử dụng createMany thay vì raw SQL để tránh SQL injection
  await tx.user.createMany({
    data: users,
    skipDuplicates: true
  })
}

async function copyAddresses(
  addresses: Array<{
    name: string
    recipient?: string
    phoneNumber?: string
    province: string
    district: string
    ward: string
    street: string
    addressType: 'HOME' | 'OFFICE' | 'OTHER'
    createdById: string
    createdAt: Date
    updatedAt: Date
  }>,
  tx: PrismaClient
): Promise<void> {
  if (addresses.length === 0) return

  await tx.address.createMany({
    data: addresses
  })
}

async function copyUserAddresses(
  userAddresses: Array<{
    userId: string
    addressId: string
    createdAt: Date
    updatedAt: Date
  }>,
  tx: PrismaClient
): Promise<void> {
  if (userAddresses.length === 0) return

  await tx.userAddress.createMany({
    data: userAddresses,
    skipDuplicates: true
  })
}

async function copyProducts(
  products: Array<{
    name: string
    description: string
    basePrice: number
    virtualPrice: number
    brandId: string
    images: string[]
    variants: any
    specifications: any
    createdById: string
    publishedAt?: Date | null
    createdAt: Date
    updatedAt: Date
  }>,
  tx: PrismaClient
): Promise<string[]> {
  if (products.length === 0) return []

  // Sử dụng createMany và sau đó query để lấy IDs
  await tx.product.createMany({
    data: products
  })

  // Lấy IDs của products vừa tạo
  const createdProducts = await tx.product.findMany({
    where: {
      name: { in: products.map((p) => p.name) },
      createdById: products[0].createdById
    },
    select: { id: true, name: true },
    orderBy: { createdAt: 'desc' },
    take: products.length
  })

  return createdProducts.map((p) => p.id)
}

async function copySKUs(
  skus: Array<{
    value: string
    price: number
    stock: number
    image: string
    productId: string
    createdById: string
    createdAt: Date
    updatedAt: Date
  }>,
  tx: PrismaClient
): Promise<void> {
  if (skus.length === 0) return

  await tx.sKU.createMany({
    data: skus
  })
}

async function copyProductTranslations(
  translations: Array<{
    productId: string
    languageId: string
    name: string
    description: string
    createdById: string
    createdAt: Date
    updatedAt: Date
  }>,
  tx: PrismaClient
): Promise<void> {
  if (translations.length === 0) return

  await tx.productTranslation.createMany({
    data: translations
  })
}

async function copyReviews(
  reviews: Array<{
    rating: number
    content: string
    userId: string
    productId: string
    orderId: string
    createdById: string
    createdAt: Date
    updatedAt: Date
  }>,
  tx: PrismaClient
): Promise<string[]> {
  if (reviews.length === 0) return []

  await tx.review.createMany({
    data: reviews
  })

  // Lấy IDs của reviews vừa tạo
  const createdReviews = await tx.review.findMany({
    where: {
      productId: { in: reviews.map((r) => r.productId) },
      orderId: { in: reviews.map((r) => r.orderId) }
    },
    select: { id: true },
    orderBy: { createdAt: 'desc' },
    take: reviews.length
  })

  return createdReviews.map((r) => r.id)
}

async function copyReviewMedia(
  media: Array<{
    url: string
    type: 'IMAGE' | 'VIDEO'
    reviewId: string
    createdAt: Date
    updatedAt: Date
  }>,
  tx: PrismaClient
): Promise<void> {
  if (media.length === 0) return

  await tx.reviewMedia.createMany({
    data: media
  })
}

// Configuration constants
const CONFIG = {
  BATCH_SIZE: 10000, // Tăng batch size để xử lý nhiều hơn
  SKU_BATCH_SIZE: 20000, // Tăng SKU batch size
  CHUNK_SIZE: 1000, // Tăng chunk size để giảm số lần gọi database
  PARALLEL_CHUNKS: 8, // Tăng số chunk song song
  COPY_BATCH_SIZE: 20000, // Tăng batch size cho COPY operations
  DEFAULT_BRAND_NAME: 'No Brand',
  VIETNAMESE_LANGUAGE_ID: 'vi',
  DEFAULT_AVATAR: 'https://shopsifu.s3.ap-southeast-1.amazonaws.com/images/b7de950e-43bd-4f32-b266-d24c080c7a1e.png',
  VIETNAMESE_PHONE_PREFIXES: ['032', '033', '034', '035', '036', '037', '038', '039']
} as const

// Vietnamese address data
const VIETNAMESE_ADDRESSES: AddressData[] = [
  // Giữ nguyên dữ liệu địa chỉ từ file gốc
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

// Interfaces (giữ nguyên từ file gốc)
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
  sellerId: string
  validImages: string[]
  validVideos: string[]
  variants: Array<{ value: string; options: string[] }>
  specifications: Array<{ name: string; value: string }>
  metadata: any
  skus: Array<{ value: string; price: number; stock: number; image: string }>
  reviews: Array<{
    clientName: string
    rating: number
    content: string
    date: string
    likes?: number
    media?: string[]
  }>
}

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

const prisma = new PrismaClient({
  log: [
    {
      emit: 'stdout',
      level: 'error'
    },
    {
      emit: 'stdout',
      level: 'warn'
    }
  ],
  datasources: {
    db: {
      url: process.env.DATABASE_URL
    }
  }
})
const hashingService = new HashingService()

// Utility functions
function generateVietnamesePhone(): string {
  const prefix = CONFIG.VIETNAMESE_PHONE_PREFIXES[Math.floor(Math.random() * CONFIG.VIETNAMESE_PHONE_PREFIXES.length)]
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

function validateProduct(product: ShopeeProduct): { isValid: boolean; reason?: string } {
  if (!product.id) return { isValid: false, reason: 'Missing ID' }
  if (!product.title?.trim()) return { isValid: false, reason: 'Missing title' }
  if (!product.final_price || product.final_price <= 0) return { isValid: false, reason: 'Invalid price' }
  if (product.stock == null || product.stock < 0) return { isValid: false, reason: 'Invalid stock' }
  if (!product.breadcrumb || product.breadcrumb.length < 2) return { isValid: false, reason: 'Invalid breadcrumb' }
  if (!product.image?.length) return { isValid: false, reason: 'No images' }
  if (!product.image.some((img) => img?.startsWith('http'))) return { isValid: false, reason: 'No valid images' }
  return { isValid: true }
}

async function ensureLanguageExists(creatorUserId: string): Promise<void> {
  if (!(await prisma.language.findUnique({ where: { id: CONFIG.VIETNAMESE_LANGUAGE_ID } }))) {
    await prisma.language.create({
      data: { id: CONFIG.VIETNAMESE_LANGUAGE_ID, name: 'Tiếng Việt', createdById: creatorUserId }
    })
  }
}

async function findCreatorUser(): Promise<{ id: string; name: string }> {
  const user =
    (await prisma.user.findFirst({
      where: { role: { name: { in: ['Admin', 'Seller'] } } }
    })) || (await prisma.user.findFirst({ orderBy: { createdAt: 'asc' } }))
  if (!user) throw new Error('No user found in database.')
  return user
}

async function optimizeDatabaseSettings(tx: PrismaClient): Promise<void> {
  await Promise.all([
    tx.$executeRaw`SET work_mem = '256MB'`,
    tx.$executeRaw`SET maintenance_work_mem = '4GB'`,
    tx.$executeRaw`SET synchronous_commit = off`,
    tx.$executeRaw`SET random_page_cost = 1.0`
  ])
}

async function resetDatabaseSettings(tx: PrismaClient): Promise<void> {
  await Promise.all([
    tx.$executeRaw`SET work_mem = '4MB'`,
    tx.$executeRaw`SET maintenance_work_mem = '64MB'`,
    tx.$executeRaw`SET synchronous_commit = on`
  ])
}

// Core processing functions
async function batchCreateBrands(
  products: ShopeeProduct[],
  creatorUserId: string,
  tx: any
): Promise<Map<string, string>> {
  const uniqueBrandNames = [...new Set(products.map((p) => p.brand || CONFIG.DEFAULT_BRAND_NAME))]
  const existingBrands = await tx.brand.findMany({
    where: { deletedAt: null, name: { in: uniqueBrandNames } },
    select: { id: true, name: true }
  })

  const existingBrandNames = new Set(existingBrands.map((b) => b.name))
  await tx.brand.updateMany({
    where: { deletedAt: null, name: { notIn: uniqueBrandNames } },
    data: { deletedAt: new Date() }
  })

  const newBrands = uniqueBrandNames.filter((name) => !existingBrandNames.has(name))
  if (newBrands.length) {
    await tx.brand.createMany({
      data: newBrands.map((name) => ({ name, logo: CONFIG.DEFAULT_AVATAR, createdById: creatorUserId })),
      skipDuplicates: true
    })
  }

  const allBrands = await tx.brand.findMany({
    where: { name: { in: uniqueBrandNames }, deletedAt: null },
    select: { id: true, name: true }
  })

  return new Map(allBrands.map((brand) => [brand.name, brand.id]))
}

async function batchCreateCategories(
  products: ShopeeProduct[],
  creatorUserId: string,
  tx: any
): Promise<Map<string, string>> {
  const categorySet = new Set<string>(['Khác'])
  const parentChildPairs = new Set<string>()

  products.forEach((p) => {
    const names = p.breadcrumb.slice(1, -1).slice(0, 2)
    if (names.length) {
      categorySet.add(names[0])
      if (names.length > 1) {
        categorySet.add(names[1])
        parentChildPairs.add(`${names[0]}|${names[1]}`)
      }
    }
  })

  const existingCategories = await tx.category.findMany({
    where: { name: { in: [...categorySet] }, deletedAt: null },
    select: { id: true, name: true, parentCategoryId: true }
  })

  const categoryMap = new Map(
    existingCategories.map((cat) => [cat.name, { id: cat.id, parentCategoryId: cat.parentCategoryId }])
  )
  const parentCategories = [...categorySet].filter(
    (name) => ![...parentChildPairs].some((pair) => pair.split('|')[1] === name)
  )
  const newParentCategories = parentCategories.filter((name) => !categoryMap.has(name))

  if (newParentCategories.length) {
    await tx.category.createMany({
      data: newParentCategories.map((name) => ({ name, createdById: creatorUserId })),
      skipDuplicates: true
    })
  }

  const updatedCategories = await tx.category.findMany({
    where: { name: { in: [...categorySet] }, deletedAt: null },
    select: { id: true, name: true, parentCategoryId: true }
  })

  categoryMap.clear()
  updatedCategories.forEach((cat) => categoryMap.set(cat.name, { id: cat.id, parentCategoryId: cat.parentCategoryId }))

  const childCategoriesToCreate = [...parentChildPairs]
    .map((pair) => {
      const [parentName, childName] = pair.split('|')
      const parentCategory = categoryMap.get(parentName)
      return parentCategory && !categoryMap.has(childName)
        ? { name: childName, parentCategoryId: (parentCategory as any).id }
        : null
    })
    .filter((cat): cat is { name: string; parentCategoryId: string } => cat !== null)

  if (childCategoriesToCreate.length) {
    await tx.category.createMany({
      data: childCategoriesToCreate.map((cat) => ({ ...cat, createdById: creatorUserId })),
      skipDuplicates: true
    })
  }

  const finalCategories = await tx.category.findMany({
    where: { name: { in: [...categorySet] }, deletedAt: null },
    select: { id: true, name: true }
  })

  return new Map(finalCategories.map((cat) => [cat.name, cat.id]))
}

async function batchCreateUsers<T extends SellerData | CustomerData>(
  entities: Map<string, ShopeeProduct | string>,
  roleName: 'SELLER' | 'CLIENT',
  creatorUserId: string,
  tx: PrismaClient
): Promise<Map<string, string>> {
  const role = await tx.role.findFirst({ where: { name: roleName } })
  if (!role) throw new Error(`${roleName} role not found`)

  const existingUsers = await tx.user.findMany({
    where: { role: { name: roleName }, deletedAt: null },
    select: { id: true, email: true }
  })

  const userMap = new Map<string, string>()
  const existingEmails = new Map(
    existingUsers.map((u) => [u.email.split('.')[0].replace(roleName.toLowerCase(), ''), u.id])
  )

  const usersToCreate: Array<{
    email: string
    name: string
    password: string
    phoneNumber: string
    avatar: string
    status: 'ACTIVE'
    roleId: string
    createdById: string
    createdAt: Date
    updatedAt: Date
    key: string
  }> = []

  // Tạo tất cả user data trước
  const userDataPromises: Promise<{
    email: string
    name: string
    password: string
    phoneNumber: string
    avatar: string
    status: 'ACTIVE'
    roleId: string
    createdById: string
    createdAt: Date
    updatedAt: Date
    key: string
  }>[] = []

  let index = 1
  for (const [key, data] of entities) {
    const email = generateEmail(roleName.toLowerCase() as 'seller' | 'client', index)
    if (existingEmails.has(key)) {
      userMap.set(key, existingEmails.get(key)!)
      index++
      continue
    }

    const name = typeof data === 'string' ? data : data.seller_name

    // Hash password song song
    userDataPromises.push(
      hashingService.hash(generatePassword(roleName.toLowerCase() as 'seller' | 'client')).then((hashedPassword) => ({
        email,
        name,
        password: hashedPassword,
        phoneNumber: generateVietnamesePhone(),
        avatar: CONFIG.DEFAULT_AVATAR,
        status: 'ACTIVE' as const,
        roleId: role.id,
        createdById: creatorUserId,
        createdAt: new Date(),
        updatedAt: new Date(),
        key
      }))
    )
    index++
  }

  // Chờ tất cả password được hash
  const userDataResults = await Promise.all(userDataPromises)
  usersToCreate.push(...userDataResults)

  // Sử dụng batch size lớn hơn cho COPY
  const copyBatchSize = CONFIG.COPY_BATCH_SIZE
  const copyChunks = Array.from({ length: Math.ceil(usersToCreate.length / copyBatchSize) }, (_, i) =>
    usersToCreate.slice(i * copyBatchSize, (i + 1) * copyBatchSize)
  )

  console.log(`📦 Processing ${usersToCreate.length} users in ${copyChunks.length} batches...`)

  for (let i = 0; i < copyChunks.length; i++) {
    const chunk = copyChunks[i]
    console.log(`🔄 Processing batch ${i + 1}/${copyChunks.length} (${chunk.length} users)...`)

    const userData = chunk.map(({ key, ...data }) => data)
    await copyUsers(userData, tx)

    // Lấy IDs của users vừa tạo
    const createdUserData = await tx.user.findMany({
      where: { email: { in: chunk.map((u) => u.email) } },
      select: { id: true, email: true }
    })

    createdUserData.forEach((u) => {
      const userData = chunk.find((c) => c.email === u.email)
      if (userData) userMap.set(userData.key, u.id)
    })
  }

  return userMap
}

async function batchCreateAddresses(
  users: Array<{ id: string }>,
  creatorUserId: string,
  tx: PrismaClient
): Promise<{ addressCount: number; userAddressCount: number }> {
  const addressesToCreate: Array<{
    name: string
    recipient?: string
    phoneNumber?: string
    province: string
    district: string
    ward: string
    street: string
    addressType: 'HOME' | 'OFFICE' | 'OTHER'
    createdById: string
    userId: string
    isDefault: boolean
    createdAt: Date
    updatedAt: Date
  }> = []

  const userAddressesToCreate: Array<{
    userId: string
    addressId: string
    createdAt: Date
    updatedAt: Date
  }> = []

  users.forEach((user) => {
    const numAddresses = Math.floor(Math.random() * 3) + 1
    for (let i = 0; i < numAddresses; i++) {
      const addressData = VIETNAMESE_ADDRESSES[Math.floor(Math.random() * VIETNAMESE_ADDRESSES.length)]
      const now = new Date()

      addressesToCreate.push({
        name: `${addressData.province} - ${addressData.district}`,
        recipient: addressData.recipient,
        phoneNumber: addressData.phoneNumber,
        province: addressData.province,
        district: addressData.district,
        ward: addressData.ward,
        street: addressData.street,
        addressType: addressData.addressType,
        createdById: creatorUserId,
        userId: user.id,
        isDefault: i === 0,
        createdAt: now,
        updatedAt: now
      })
    }
  })

  let addressCount = 0
  let userAddressCount = 0

  // Sử dụng COPY operations với batch size lớn hơn
  const copyBatchSize = CONFIG.COPY_BATCH_SIZE
  const copyChunks = Array.from({ length: Math.ceil(addressesToCreate.length / copyBatchSize) }, (_, i) =>
    addressesToCreate.slice(i * copyBatchSize, (i + 1) * copyBatchSize)
  )

  for (const chunk of copyChunks) {
    // Tạo addresses
    const addressData = chunk.map(({ userId, isDefault, ...data }) => data)
    await copyAddresses(addressData, tx)

    // Lấy IDs của addresses vừa tạo
    const createdAddressData = await tx.address.findMany({
      where: { name: { in: chunk.map((a) => a.name) } },
      select: { id: true, name: true }
    })

    // Tạo user addresses
    const userAddresses = chunk
      .map((address) => {
        const createdAddress = createdAddressData.find((a) => a.name === address.name)
        return createdAddress
          ? {
              userId: address.userId,
              addressId: createdAddress.id,
              createdAt: address.createdAt,
              updatedAt: address.updatedAt
            }
          : null
      })
      .filter((ua): ua is { userId: string; addressId: string; createdAt: Date; updatedAt: Date } => ua !== null)

    if (userAddresses.length) {
      await copyUserAddresses(userAddresses, tx)
    }

    addressCount += chunk.length
    userAddressCount += userAddresses.length
  }

  return { addressCount, userAddressCount }
}

function generateEnhancedVariants(
  variations?: Array<{ name: string; variations: string[] }> | null
): Array<{ value: string; options: string[] }> {
  if (!variations?.length) return [{ value: 'Default', options: ['Default'] }]
  const variants = variations.filter((v) => v.variations?.length).map((v) => ({ value: v.name, options: v.variations }))
  return variants.length ? variants : [{ value: 'Default', options: ['Default'] }]
}

function generateProductSpecifications(product?: ShopeeProduct): Array<{ name: string; value: string }> {
  return product?.['Product Specifications'] || []
}

function generateProductMetadata(product?: ShopeeProduct): any {
  if (!product) return null
  return {
    metrics: {
      shopeeRating: product.rating || 0,
      shopeeReviews: product.reviews || 0,
      shopeeFavorites: product.favorite || 0,
      shopeeSold: product.sold || 0
    },
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

function generateSKUs(
  variants: Array<{ value: string; options: string[] }>,
  basePrice: number,
  stock: number,
  images: string[]
): Array<{ value: string; price: number; stock: number; image: string }> {
  if (!variants.length || variants[0].value === 'Default') {
    return [{ value: 'Default', price: basePrice, stock, image: images[0] || '' }]
  }

  const combinations = variants.reduce((acc: string[][], v) => {
    const result: string[][] = []
    const options = v.options
    if (!acc.length) return options.map((o) => [o])
    for (const item of acc) {
      for (const option of options) {
        result.push([...item, option])
      }
    }
    return result
  }, [])

  const stockPerSku = Math.max(1, Math.floor(stock / combinations.length))
  const remainingStock = stock - stockPerSku * combinations.length

  return combinations.map((combo, index) => ({
    value: combo.join(' - '),
    price: basePrice,
    stock: index === 0 ? stockPerSku + remainingStock : stockPerSku,
    image: images[index % Math.max(1, images.length)] || images[0] || ''
  }))
}

async function processProductsBatch(
  products: ShopeeProduct[],
  brandMap: Map<string, string>,
  categoryMap: Map<string, string>,
  sellerMap: Map<string, string>
): Promise<ProcessedProduct[]> {
  return Promise.all(
    Array.from({ length: Math.ceil(products.length / CONFIG.CHUNK_SIZE) }, (_, i) =>
      products.slice(i * CONFIG.CHUNK_SIZE, (i + 1) * CONFIG.CHUNK_SIZE).map((product) => {
        const brandId = brandMap.get(product.brand || CONFIG.DEFAULT_BRAND_NAME)
        if (!brandId) throw new Error(`Brand not found: ${product.brand || CONFIG.DEFAULT_BRAND_NAME}`)

        const categoryNames = product.breadcrumb.slice(1, -1).slice(0, 2)
        const categoryId =
          categoryNames.length === 0
            ? categoryMap.get('Khác')!
            : categoryMap.get(categoryNames[1]) || categoryMap.get(categoryNames[0])!
        if (!categoryId) throw new Error(`Category not found: ${categoryNames.join(' > ')}`)

        const validImages = product.image.filter((img) => img?.startsWith('http'))
        const validVideos = product.video?.filter((vid) => vid?.startsWith('http')) || []
        const variants = generateEnhancedVariants(product.variations)
        const skus = generateSKUs(variants, product.final_price, product.stock, [...validImages, ...validVideos])
        const specifications = generateProductSpecifications(product)
        const metadata = generateProductMetadata(product)
        const reviews = (product.product_ratings || []).map((rating) => ({
          clientName: rating.customer_name,
          rating: rating.rating_stars,
          content: rating.review,
          date: rating.review_date,
          likes: rating.review_likes,
          media: rating.review_media
        }))

        return {
          shopeeData: product,
          brandId,
          categoryId,
          sellerId: sellerMap.get(product.seller_id) || '',
          validImages,
          validVideos,
          variants,
          specifications,
          metadata,
          skus,
          reviews
        }
      })
    ).flat()
  )
}

async function batchCreateReviews(
  processedProducts: ProcessedProduct[],
  productMap: Map<string, string>,
  clientMap: Map<string, string>,
  tx: PrismaClient
): Promise<{ success: number; failed: number }> {
  let successCount = 0
  let failedCount = 0

  const defaultUser =
    (await tx.user.findFirst({ where: { role: { name: { in: ['CLIENT', 'USER'] } } } })) ||
    (await tx.user.findFirst({ orderBy: { createdAt: 'asc' } }))
  if (!defaultUser) return { success: 0, failed: 0 }

  const reviewsData: Array<{
    content: string
    rating: number
    productId: string
    userId: string
    orderId: string
    createdAt: Date
    media?: string[]
  }> = []
  const paymentsData: Array<{ status: 'SUCCESS' }> = []
  const ordersData: Array<{
    userId: string
    status: 'DELIVERED'
    paymentId: string
    shopId: string | null
    receiver: any
    createdAt: Date
  }> = []

  processedProducts.forEach((processed) => {
    const productId = productMap.get(processed.shopeeData.title)
    if (!productId || !processed.reviews?.length) return

    processed.reviews.forEach((review) => {
      if (!review.content?.trim()) return

      const clientUserId = clientMap.get(review.clientName) || defaultUser.id
      paymentsData.push({ status: 'SUCCESS' })
      ordersData.push({
        userId: clientUserId,
        status: 'DELIVERED',
        paymentId: '',
        shopId: processed.sellerId || null,
        receiver: { name: review.clientName || 'Anonymous', phone: '0000000000', address: 'N/A' },
        createdAt: new Date(review.date)
      })
      reviewsData.push({
        content: review.content.trim(),
        rating: Math.max(1, Math.min(5, review.rating)),
        productId,
        userId: clientUserId,
        orderId: '',
        createdAt: new Date(review.date),
        media: review.media
      })
    })
  })

  const chunks = Array.from({ length: Math.ceil(reviewsData.length / CONFIG.CHUNK_SIZE) }, (_, i) => ({
    reviews: reviewsData.slice(i * CONFIG.CHUNK_SIZE, (i + 1) * CONFIG.CHUNK_SIZE),
    payments: paymentsData.slice(i * CONFIG.CHUNK_SIZE, (i + 1) * CONFIG.CHUNK_SIZE),
    orders: ordersData.slice(i * CONFIG.CHUNK_SIZE, (i + 1) * CONFIG.CHUNK_SIZE)
  }))

  await Promise.all(
    chunks.map(async ({ reviews, payments, orders }) => {
      try {
        const { createdReviews, reviewIds } = await tx.$transaction(async (tx) => {
          const createdPayments = await tx.payment.createMany({ data: payments })
          const paymentIds = await tx.payment.findMany({
            where: { status: 'SUCCESS' },
            orderBy: { createdAt: 'desc' },
            take: payments.length,
            select: { id: true }
          })

          const ordersWithPaymentIds = orders.map((order, index) => ({
            ...order,
            paymentId: paymentIds[index]?.id || ''
          }))

          await tx.order.createMany({ data: ordersWithPaymentIds })
          const orderIds = await tx.order.findMany({
            where: { status: 'DELIVERED' },
            orderBy: { createdAt: 'desc' },
            take: orders.length,
            select: { id: true }
          })

          const reviewsWithOrderIds = reviews.map((review, index) => ({
            ...review,
            orderId: orderIds[index]?.id || ''
          }))

          const createdReviews = await tx.review.createMany({
            data: reviewsWithOrderIds.map(({ media, ...data }) => data),
            skipDuplicates: true
          })

          const reviewIds = await tx.review.findMany({
            where: { content: { in: reviews.map((r) => r.content) } },
            orderBy: { createdAt: 'desc' },
            take: reviews.length,
            select: { id: true }
          })

          return { createdReviews, reviewIds }
        })

        const mediaToCreate = reviews
          .flatMap(
            (review, index) =>
              review.media
                ?.filter((url) => url?.startsWith('http'))
                .map((url) => ({
                  url,
                  type: (url.includes('.mp4') || url.includes('video') ? 'VIDEO' : 'IMAGE') as 'IMAGE' | 'VIDEO',
                  reviewId: reviewIds[index]?.id || ''
                })) || []
          )
          .filter((media) => media.reviewId)

        if (mediaToCreate.length) {
          await tx.reviewMedia.createMany({ data: mediaToCreate, skipDuplicates: true })
        }

        successCount += createdReviews.count
      } catch (error) {
        console.error(`❌ Failed to create reviews batch`, error)
        failedCount += reviews.length
      }
    })
  )

  return { success: successCount, failed: failedCount }
}

async function batchCreateProducts(
  processedProducts: ProcessedProduct[],
  creatorUserId: string,
  tx: PrismaClient
): Promise<{ success: number; failed: number }> {
  let successCount = 0
  let failedCount = 0

  await optimizeDatabaseSettings(tx)

  // Sử dụng COPY operations với batch size lớn hơn
  const copyBatchSize = CONFIG.COPY_BATCH_SIZE
  const copyChunks = Array.from({ length: Math.ceil(processedProducts.length / copyBatchSize) }, (_, i) =>
    processedProducts.slice(i * copyBatchSize, (i + 1) * copyBatchSize)
  )

  for (const chunk of copyChunks) {
    try {
      const now = new Date()

      // Chuẩn bị dữ liệu products
      const productsData = chunk.map((processed) => ({
        name: processed.shopeeData.title,
        description: processed.shopeeData['Product Description'] || '',
        basePrice: processed.shopeeData.final_price,
        virtualPrice: processed.shopeeData.initial_price,
        brandId: processed.brandId,
        images: [...processed.validImages, ...processed.validVideos],
        variants: processed.variants,
        specifications: processed.specifications.length ? processed.specifications : null,
        createdById: creatorUserId,
        publishedAt: processed.shopeeData.is_available ? now : null,
        createdAt: now,
        updatedAt: now
      }))

      // Tạo products bằng COPY
      const productIds = await copyProducts(productsData, tx)

      // Chuẩn bị dữ liệu SKUs
      const skusData = chunk.flatMap((processed, index) =>
        processed.skus.map((sku) => ({
          ...sku,
          productId: productIds[index],
          createdById: creatorUserId,
          createdAt: now,
          updatedAt: now
        }))
      )

      // Chuẩn bị dữ liệu translations
      const translationsData = chunk.map((processed, index) => ({
        productId: productIds[index],
        languageId: CONFIG.VIETNAMESE_LANGUAGE_ID,
        name: processed.shopeeData.title,
        description: processed.shopeeData['Product Description'] || '',
        createdById: creatorUserId,
        createdAt: now,
        updatedAt: now
      }))

      // Tạo SKUs bằng COPY với batch size lớn
      const skuCopyBatchSize = CONFIG.SKU_BATCH_SIZE
      const skuCopyChunks = Array.from({ length: Math.ceil(skusData.length / skuCopyBatchSize) }, (_, i) =>
        skusData.slice(i * skuCopyBatchSize, (i + 1) * skuCopyBatchSize)
      )

      for (const skuChunk of skuCopyChunks) {
        await copySKUs(skuChunk, tx)
      }

      // Tạo translations bằng COPY
      if (translationsData.length) {
        await copyProductTranslations(translationsData, tx)
      }

      successCount += chunk.length
    } catch (error) {
      console.error(`❌ Failed to create products batch`, error)
      failedCount += chunk.length
    }
  }

  await resetDatabaseSettings(tx)
  return { success: successCount, failed: failedCount }
}

async function readJsonStream(jsonPath: string): Promise<ShopeeProduct[]> {
  try {
    const fileContent = fs.readFileSync(jsonPath, 'utf8')
    const products: ShopeeProduct[] = JSON.parse(fileContent)
    console.log(`📁 Read ${products.length} products from JSON file`)
    return products
  } catch (error) {
    console.error('❌ Error reading JSON file:', error)
    return []
  }
}

async function importProductsOptimized(): Promise<void> {
  let timeout: NodeJS.Timeout | null = null
  try {
    console.log('🚀 Starting optimized product import...')

    // Tối ưu connection pool cho script import
    await prisma.$connect()
    console.log('✅ Connected to database')

    // Set timeout cho database operations
    timeout = setTimeout(
      () => {
        console.error('⏰ Database operation timeout after 15 minutes')
        process.exit(1)
      },
      15 * 60 * 1000
    ) // 15 phút timeout
    const creatorUser = await findCreatorUser()
    await ensureLanguageExists(creatorUser.id)

    const jsonPath = path.join(process.cwd(), 'initialScript', 'product', 'data', 'Shopee-products.json')
    if (!fs.existsSync(jsonPath)) throw new Error('Shopee-products.json not found')

    const productBatches: ShopeeProduct[] = await readJsonStream(jsonPath)
    console.log(`📊 Loaded ${productBatches.length} products from JSON file`)

    const validationStats: { [key: string]: number } = {
      'Missing ID': 0,
      'Missing title': 0,
      'Invalid price': 0,
      'Invalid stock': 0,
      'Invalid breadcrumb': 0,
      'No images': 0,
      'No valid images': 0
    }
    let validProducts: ShopeeProduct[] = []

    const validated = await Promise.all(
      productBatches.map(async (product) => {
        const validation = validateProduct(product)
        if (!validation.isValid) validationStats[validation.reason!] = (validationStats[validation.reason!] || 0) + 1
        return validation.isValid ? product : null
      })
    )
    validProducts.push(...validated.filter((p): p is ShopeeProduct => p !== null))

    console.log(
      `✅ Validated products: ${validProducts.length} valid, ${Object.values(validationStats).reduce((a, b) => a + b, 0)} invalid`
    )
    console.log('📈 Validation breakdown:', validationStats)

    if (!validProducts.length) {
      console.log('❌ No valid products to import')
      return
    }

    // Sync logic giống create-permissions.ts
    console.log('🔄 Starting data synchronization...')

    // 1. Sync Products
    console.log('📦 Syncing products...')
    const existingProducts = await prisma.product.findMany({
      where: { deletedAt: null },
      select: { id: true, name: true }
    })

    const validProductNames = new Map(validProducts.map((p) => [p.title, p]))
    const existingProductNames = new Set(existingProducts.map((p) => p.name))

    // Xóa products không còn trong JSON
    const productsToDelete = existingProducts.filter((p) => !validProductNames.has(p.name))
    if (productsToDelete.length > 0) {
      console.log(`🗑️ Deleting ${productsToDelete.length} outdated products...`)
      await prisma.product.deleteMany({ where: { id: { in: productsToDelete.map((p) => p.id) } } })
      console.log(`✅ Deleted ${productsToDelete.length} outdated products`)
    } else {
      console.log('✅ No outdated products to delete')
    }

    // Thêm products mới
    const productsToAdd = validProducts.filter((p) => !existingProductNames.has(p.title))
    if (!productsToAdd.length) {
      console.log('✅ No new products to add')
      return
    }
    console.log(`📥 Adding ${productsToAdd.length} new products...`)

    // 2. Sync Brands
    console.log('🏷️ Syncing brands...')
    const uniqueBrandNames = [...new Set(productsToAdd.map((p) => p.brand || CONFIG.DEFAULT_BRAND_NAME))]
    const existingBrands = await prisma.brand.findMany({
      where: { deletedAt: null },
      select: { id: true, name: true }
    })

    const existingBrandNames = new Set(existingBrands.map((b) => b.name))
    const brandsToDelete = existingBrands.filter((b) => !uniqueBrandNames.includes(b.name))
    const brandsToAdd = uniqueBrandNames.filter((name) => !existingBrandNames.has(name))

    if (brandsToDelete.length > 0) {
      console.log(`🗑️ Deleting ${brandsToDelete.length} outdated brands...`)
      await prisma.brand.updateMany({
        where: { id: { in: brandsToDelete.map((b) => b.id) } },
        data: { deletedAt: new Date() }
      })
      console.log(`✅ Deleted ${brandsToDelete.length} outdated brands`)
    }

    if (brandsToAdd.length > 0) {
      console.log(`📥 Adding ${brandsToAdd.length} new brands...`)
      await prisma.brand.createMany({
        data: brandsToAdd.map((name) => ({ name, logo: CONFIG.DEFAULT_AVATAR, createdById: creatorUser.id })),
        skipDuplicates: true
      })
      console.log(`✅ Added ${brandsToAdd.length} new brands`)
    }

    // 3. Sync Categories
    console.log('📂 Syncing categories...')
    const categorySet = new Set<string>(['Khác'])
    const parentChildPairs = new Set<string>()

    productsToAdd.forEach((p) => {
      const names = p.breadcrumb.slice(1, -1).slice(0, 2)
      if (names.length) {
        categorySet.add(names[0])
        if (names.length > 1) {
          categorySet.add(names[1])
          parentChildPairs.add(`${names[0]}|${names[1]}`)
        }
      }
    })

    const existingCategories = await prisma.category.findMany({
      where: { deletedAt: null },
      select: { id: true, name: true, parentCategoryId: true }
    })

    const existingCategoryNames = new Set(existingCategories.map((c) => c.name))
    const categoriesToDelete = existingCategories.filter((c) => !categorySet.has(c.name))
    const categoriesToAdd = [...categorySet].filter((name) => !existingCategoryNames.has(name))

    if (categoriesToDelete.length > 0) {
      console.log(`🗑️ Deleting ${categoriesToDelete.length} outdated categories...`)
      await prisma.category.updateMany({
        where: { id: { in: categoriesToDelete.map((c) => c.id) } },
        data: { deletedAt: new Date() }
      })
      console.log(`✅ Deleted ${categoriesToDelete.length} outdated categories`)
    }

    if (categoriesToAdd.length > 0) {
      console.log(`📥 Adding ${categoriesToAdd.length} new categories...`)
      await prisma.category.createMany({
        data: categoriesToAdd.map((name) => ({ name, createdById: creatorUser.id })),
        skipDuplicates: true
      })
      console.log(`✅ Added ${categoriesToAdd.length} new categories`)
    }

    // 4. Sync Users (Sellers & Customers)
    console.log('👥 Syncing users...')
    const uniqueSellers = new Map(
      productsToAdd
        .map((p) => [p.seller_id, p])
        .filter(([_, p]) => (p as ShopeeProduct).seller_id && (p as ShopeeProduct).seller_name) as [
        string,
        ShopeeProduct
      ][]
    )

    const uniqueCustomers = new Map(
      productsToAdd
        .flatMap((p) => p.product_ratings?.map((r) => [r.customer_name, r.customer_name]) || [])
        .filter(([name]) => name) as [string, string][]
    )

    // Sync sellers
    const existingSellers = await prisma.user.findMany({
      where: { role: { name: 'SELLER' }, deletedAt: null },
      select: { id: true, email: true }
    })

    const sellerEmails = Array.from(uniqueSellers.keys()).map((_, index) => generateEmail('seller', index + 1))
    const existingSellerEmails = new Set(existingSellers.map((s) => s.email))
    const sellersToDelete = existingSellers.filter((s) => !sellerEmails.includes(s.email))
    const sellersToAdd = sellerEmails.filter((email) => !existingSellerEmails.has(email))

    if (sellersToDelete.length > 0) {
      console.log(`🗑️ Deleting ${sellersToDelete.length} outdated sellers...`)
      await prisma.user.updateMany({
        where: { id: { in: sellersToDelete.map((s) => s.id) } },
        data: { deletedAt: new Date() }
      })
      console.log(`✅ Deleted ${sellersToDelete.length} outdated sellers`)
    }

    // Sync customers
    const existingCustomers = await prisma.user.findMany({
      where: { role: { name: 'CLIENT' }, deletedAt: null },
      select: { id: true, email: true }
    })

    const customerEmails = Array.from(uniqueCustomers.keys()).map((_, index) => generateEmail('client', index + 1))
    const existingCustomerEmails = new Set(existingCustomers.map((c) => c.email))
    const customersToDelete = existingCustomers.filter((c) => !customerEmails.includes(c.email))
    const customersToAdd = customerEmails.filter((email) => !existingCustomerEmails.has(email))

    if (customersToDelete.length > 0) {
      console.log(`🗑️ Deleting ${customersToDelete.length} outdated customers...`)
      await prisma.user.updateMany({
        where: { id: { in: customersToDelete.map((c) => c.id) } },
        data: { deletedAt: new Date() }
      })
      console.log(`✅ Deleted ${customersToDelete.length} outdated customers`)
    }

    // 5. Sync Addresses
    console.log('📍 Syncing addresses...')
    const allUsers = await prisma.user.findMany({ where: { deletedAt: null }, select: { id: true } })
    const existingAddresses = await prisma.address.findMany({
      where: { deletedAt: null },
      select: { id: true, name: true }
    })

    // Tính toán số lượng addresses cần thiết (mỗi user có 1-3 addresses)
    const requiredAddressCount = allUsers.length * 2 // Giả sử mỗi user có 2 addresses
    const addressesToDelete =
      existingAddresses.length > requiredAddressCount ? existingAddresses.slice(requiredAddressCount) : []

    if (addressesToDelete.length > 0) {
      console.log(`🗑️ Deleting ${addressesToDelete.length} excess addresses...`)
      await prisma.address.updateMany({
        where: { id: { in: addressesToDelete.map((a) => a.id) } },
        data: { deletedAt: new Date() }
      })
      console.log(`✅ Deleted ${addressesToDelete.length} excess addresses`)
    }

    console.log('✅ Data synchronization completed')

    // Tiếp tục với việc tạo dữ liệu mới
    let brandMap: Map<string, string> = new Map(),
      categoryMap: Map<string, string> = new Map(),
      sellerMap: Map<string, string>,
      clientMap: Map<string, string>

    console.log('🏷️ Creating brands...')
    brandMap = await batchCreateBrands(productsToAdd, creatorUser.id, prisma)
    console.log(`✅ Created ${brandMap.size} brands`)

    console.log('📂 Creating categories...')
    categoryMap = await batchCreateCategories(productsToAdd, creatorUser.id, prisma)
    console.log(`✅ Created ${categoryMap.size} categories`)

    console.log('👥 Creating sellers...')
    sellerMap = await batchCreateUsers(uniqueSellers as Map<string, ShopeeProduct>, 'SELLER', creatorUser.id, prisma)
    console.log(`✅ Created ${sellerMap.size} sellers`)

    console.log('👤 Creating customers...')
    clientMap = await batchCreateUsers(uniqueCustomers as Map<string, string>, 'CLIENT', creatorUser.id, prisma)
    console.log(`✅ Created ${clientMap.size} customers`)

    console.log('📍 Creating addresses...')
    const addressResult = await batchCreateAddresses(allUsers, creatorUser.id, prisma)
    console.log(
      `✅ Created ${addressResult.addressCount} addresses and ${addressResult.userAddressCount} user-address relationships`
    )

    console.log('🔄 Processing products...')
    const processedProducts = await processProductsBatch(productsToAdd, brandMap, categoryMap, sellerMap)
    console.log(`✅ Processed ${processedProducts.length} products`)

    console.log('📦 Creating products...')
    const productResult = await batchCreateProducts(processedProducts, creatorUser.id, prisma)
    console.log(`✅ Created ${productResult.success} products, failed: ${productResult.failed}`)

    console.log('📝 Creating reviews...')
    const productNameToIdMap = new Map(
      (
        await prisma.product.findMany({
          where: { name: { in: processedProducts.map((p) => p.shopeeData.title) }, deletedAt: null },
          select: { id: true, name: true }
        })
      ).map((p) => [p.name, p.id])
    )

    const reviewResult = await batchCreateReviews(processedProducts, productNameToIdMap, clientMap, prisma)
    console.log(`✅ Created ${reviewResult.success} reviews, failed: ${reviewResult.failed}`)

    console.log('\n🎉 Import Summary:', {
      totalProducts: validProducts.length + Object.values(validationStats).reduce((a, b) => a + b, 0),
      validProducts: validProducts.length,
      invalidProducts: Object.values(validationStats).reduce((a, b) => a + b, 0),
      existingProducts: existingProducts.length,
      productsDeleted: productsToDelete.length,
      productsAdded: productsToAdd.length,
      attemptedImport: productsToAdd.length,
      successfulImports: productResult.success,
      failedImports: productResult.failed,
      reviewsCreated: reviewResult.success,
      reviewsFailed: reviewResult.failed,
      brandsCreated: brandMap.size,
      categoriesCreated: categoryMap.size,
      sellersCreated: sellerMap.size,
      customersCreated: clientMap.size,
      addressesCreated: addressResult.addressCount,
      userAddressRelationships: addressResult.userAddressCount
    })
  } catch (error) {
    console.error('❌ Fatal error during import:', error)
    throw error
  } finally {
    if (timeout) clearTimeout(timeout)
    await prisma.$disconnect()
    console.log('🔌 Disconnected from database')
  }
}

export { importProductsOptimized }

if (require.main === module) {
  importProductsOptimized()
    .then(() => console.log('🎯 Optimized import completed'))
    .catch((error) => {
      console.error('💥 Optimized import failed:', error)
      process.exit(1)
    })
}
