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
  // Kiểm tra các trường bắt buộc
  if (!product.id?.trim()) return { isValid: false, reason: 'Missing ID' }
  if (!product.title?.trim()) return { isValid: false, reason: 'Missing title' }
  if (!product.final_price || product.final_price <= 0) return { isValid: false, reason: 'Invalid price' }
  if (product.stock == null || product.stock < 0) return { isValid: false, reason: 'Invalid stock' }
  if (!product.breadcrumb || product.breadcrumb.length < 2) return { isValid: false, reason: 'Invalid breadcrumb' }
  if (!product.image?.length) return { isValid: false, reason: 'No images' }
  if (!product.image.some((img) => img?.startsWith('http'))) return { isValid: false, reason: 'No valid images' }

  // Kiểm tra seller info
  if (!product.seller_id?.trim()) return { isValid: false, reason: 'Missing seller ID' }
  if (!product.seller_name?.trim()) return { isValid: false, reason: 'Missing seller name' }

  // Kiểm tra title length (tránh quá dài)
  if (product.title.length > 500) return { isValid: false, reason: 'Title too long' }

  // Kiểm tra price hợp lý
  if (product.final_price > 1000000000) return { isValid: false, reason: 'Price too high' }

  // Kiểm tra stock hợp lý
  if (product.stock > 1000000000) return { isValid: false, reason: 'Stock too high' }

  // Kiểm tra rating hợp lệ
  if (product.rating < 0 || product.rating > 5) return { isValid: false, reason: 'Invalid rating' }

  // Kiểm tra reviews count hợp lệ
  if (product.reviews < 0) return { isValid: false, reason: 'Invalid reviews count' }

  // Kiểm tra currency
  if (!product.currency || !['VND', 'USD'].includes(product.currency)) {
    return { isValid: false, reason: 'Invalid currency' }
  }

  // Kiểm tra brand name length
  if (product.brand && product.brand.length > 100) {
    return { isValid: false, reason: 'Brand name too long' }
  }

  // Kiểm tra description length
  if (product['Product Description'] && product['Product Description'].length > 10000) {
    return { isValid: false, reason: 'Description too long' }
  }

  // Kiểm tra image URLs hợp lệ
  const invalidImages = product.image.filter((img) => !img?.startsWith('http') || img.length > 1000)
  if (invalidImages.length > 0) return { isValid: false, reason: 'Invalid image URLs' }

  // Kiểm tra video URLs hợp lệ (nếu có)
  if (product.video) {
    const invalidVideos = product.video.filter((vid) => !vid?.startsWith('http') || vid.length > 1000)
    if (invalidVideos.length > 0) return { isValid: false, reason: 'Invalid video URLs' }
  }

  // Kiểm tra breadcrumb hợp lệ
  const invalidBreadcrumb = product.breadcrumb.filter((item) => !item?.trim() || item.length > 200)
  if (invalidBreadcrumb.length > 0) return { isValid: false, reason: 'Invalid breadcrumb items' }

  // Kiểm tra specifications hợp lệ
  if (product['Product Specifications']) {
    const invalidSpecs = product['Product Specifications'].filter(
      (spec) => !spec.name?.trim() || spec.name.length > 200 || !spec.value?.trim() || spec.value.length > 1000
    )
    if (invalidSpecs.length > 0) return { isValid: false, reason: 'Invalid specifications' }
  }

  // Kiểm tra variations hợp lệ
  if (product.variations) {
    const invalidVariations = product.variations.filter(
      (variation) =>
        !variation.name?.trim() ||
        variation.name.length > 200 ||
        !variation.variations?.length ||
        variation.variations.some((v) => !v?.trim() || v.length > 200)
    )
    if (invalidVariations.length > 0) return { isValid: false, reason: 'Invalid variations' }
  }

  // Kiểm tra product_variation hợp lệ
  if (product.product_variation) {
    const invalidProductVariations = product.product_variation.filter((pv) => !pv.name?.trim() || pv.name.length > 200)
    if (invalidProductVariations.length > 0) return { isValid: false, reason: 'Invalid product variations' }
  }

  // Kiểm tra reviews hợp lệ
  if (product.product_ratings) {
    const invalidReviews = product.product_ratings.filter(
      (review) =>
        !review.customer_name?.trim() ||
        review.customer_name.length > 200 ||
        review.rating_stars < 1 ||
        review.rating_stars > 5 ||
        !review.review?.trim() ||
        review.review.length > 5000 ||
        !review.review_date?.trim()
    )
    if (invalidReviews.length > 0) return { isValid: false, reason: 'Invalid reviews' }
  }

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

  // Validation: Kiểm tra variants hợp lệ
  const validVariants = variants.filter(
    (v) => v.value?.trim() && v.options?.length && v.options.every((opt) => opt?.trim())
  )

  if (!validVariants.length) {
    return [{ value: 'Default', price: basePrice, stock, image: images[0] || '' }]
  }

  // Tạo tất cả combinations có thể
  const combinations = validVariants.reduce((acc: string[][], v) => {
    const result: string[][] = []
    const options = v.options.filter((opt) => opt?.trim()) // Lọc bỏ options rỗng

    if (acc.length === 0) {
      return options.map((opt) => [opt])
    }

    for (const existing of acc) {
      for (const option of options) {
        result.push([...existing, option])
      }
    }
    return result
  }, [])

  // Validation: Kiểm tra số lượng combinations hợp lý
  if (combinations.length > 100) {
    console.warn(`⚠️ Too many SKU combinations (${combinations.length}), limiting to 100`)
    combinations.splice(100)
  }

  // Tạo SKUs với validation
  const skus: Array<{ value: string; price: number; stock: number; image: string }> = []
  const usedValues = new Set<string>() // Để tránh trùng variant

  for (let i = 0; i < combinations.length; i++) {
    const combination = combinations[i]
    const value = combination.join(' - ')

    // Kiểm tra trùng variant
    if (usedValues.has(value)) {
      console.warn(`⚠️ Duplicate variant detected: ${value}, skipping`)
      continue
    }
    usedValues.add(value)

    // Tính toán price và stock cho từng SKU
    const priceVariation = Math.random() * 0.2 - 0.1 // ±10% variation
    const price = Math.max(1, Math.round(basePrice * (1 + priceVariation)))

    const stockVariation = Math.random() * 0.5 + 0.5 // 50-100% of base stock
    const skuStock = Math.max(0, Math.round(stock * stockVariation))

    // Chọn image cho SKU
    const imageIndex = i % images.length
    const image = images[imageIndex] || images[0] || ''

    skus.push({
      value: value.length > 200 ? value.substring(0, 200) : value, // Giới hạn độ dài
      price,
      stock: skuStock,
      image
    })
  }

  // Đảm bảo có ít nhất 1 SKU
  if (skus.length === 0) {
    skus.push({
      value: 'Default',
      price: basePrice,
      stock,
      image: images[0] || ''
    })
  }

  return skus
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

  const allReviews: Array<{
    rating: number
    content: string
    userId: string
    productId: string
    orderId: string
    createdById: string
    createdAt: Date
    updatedAt: Date
  }> = []

  const allReviewMedia: Array<{
    url: string
    type: 'IMAGE' | 'VIDEO'
    reviewId: string
    createdAt: Date
    updatedAt: Date
  }> = []

  // Validation: Kiểm tra trùng lặp reviews trong database
  const existingReviews = await tx.review.findMany({
    select: { id: true, content: true, userId: true, productId: true }
  })

  const existingReviewKey = new Set(
    existingReviews.map((r) => `${r.userId}-${r.productId}-${r.content.substring(0, 50)}`)
  )

  for (const processed of processedProducts) {
    const productId = productMap.get(processed.shopeeData.title)
    if (!productId) continue

    // Validation: Kiểm tra reviews hợp lệ
    const validReviews = processed.reviews.filter((review) => {
      // Kiểm tra dữ liệu cơ bản
      if (!review.clientName?.trim()) {
        console.warn(`⚠️ Review missing client name for product ${processed.shopeeData.title}, skipping`)
        return false
      }
      if (!review.content?.trim()) {
        console.warn(`⚠️ Review missing content for product ${processed.shopeeData.title}, skipping`)
        return false
      }
      if (review.rating < 1 || review.rating > 5) {
        console.warn(
          `⚠️ Review has invalid rating ${review.rating} for product ${processed.shopeeData.title}, skipping`
        )
        return false
      }
      if (review.content.length > 5000) {
        console.warn(`⚠️ Review content too long for product ${processed.shopeeData.title}, skipping`)
        return false
      }

      // Kiểm tra trùng lặp
      const clientId = clientMap.get(review.clientName)
      if (!clientId) {
        console.warn(`⚠️ Review client not found: ${review.clientName}, skipping`)
        return false
      }

      const reviewKey = `${clientId}-${productId}-${review.content.substring(0, 50)}`
      if (existingReviewKey.has(reviewKey)) {
        console.warn(`⚠️ Duplicate review detected for product ${processed.shopeeData.title}, skipping`)
        return false
      }

      existingReviewKey.add(reviewKey)
      return true
    })

    for (const review of validReviews) {
      const clientId = clientMap.get(review.clientName)
      if (!clientId) continue

      // Tạo fake payment trước
      const fakePayment = await tx.payment.create({
        data: {
          status: 'SUCCESS',
          createdAt: new Date(),
          updatedAt: new Date()
        }
      })

      // Tạo fake order cho review với paymentId
      const fakeOrder = await tx.order.create({
        data: {
          userId: clientId,
          status: 'DELIVERED',
          receiver: {
            name: review.clientName,
            phone: generateVietnamesePhone(),
            address: 'Fake address for review'
          },
          shopId: processed.sellerId,
          paymentId: fakePayment.id,
          createdById: clientId,
          createdAt: new Date(),
          updatedAt: new Date()
        }
      })

      const now = new Date()
      allReviews.push({
        rating: review.rating,
        content: review.content,
        userId: clientId,
        productId,
        orderId: fakeOrder.id,
        createdById: clientId,
        createdAt: now,
        updatedAt: now
      })
    }
  }

  // Tạo reviews theo batch
  const reviewBatchSize = CONFIG.COPY_BATCH_SIZE
  const reviewBatches = Array.from({ length: Math.ceil(allReviews.length / reviewBatchSize) }, (_, i) =>
    allReviews.slice(i * reviewBatchSize, (i + 1) * reviewBatchSize)
  )

  for (const batch of reviewBatches) {
    if (batch.length === 0) continue

    try {
      const reviewIds = await copyReviews(batch, tx)

      // Tạo review media nếu có
      for (let i = 0; i < batch.length; i++) {
        const review = batch[i]
        const reviewId = reviewIds[i]
        if (!reviewId) continue

        const processed = processedProducts.find((p) => productMap.get(p.shopeeData.title) === review.productId)

        if (processed) {
          const reviewData = processed.reviews.find(
            (r) => clientMap.get(r.clientName) === review.userId && r.content === review.content
          )

          if (reviewData?.media?.length) {
            const mediaToCreate = reviewData.media
              .filter((url) => url?.startsWith('http'))
              .slice(0, 5) // Giới hạn 5 media per review
              .map((url) => ({
                url,
                type: (url.includes('.mp4') || url.includes('video') ? 'VIDEO' : 'IMAGE') as 'IMAGE' | 'VIDEO',
                reviewId,
                createdAt: review.createdAt,
                updatedAt: review.updatedAt
              }))

            if (mediaToCreate.length > 0) {
              allReviewMedia.push(...mediaToCreate)
            }
          }
        }
      }

      successCount += batch.length
    } catch (error) {
      console.error(`❌ Failed to create reviews batch:`, error)
      failedCount += batch.length
    }
  }

  // Tạo review media theo batch
  const mediaBatchSize = CONFIG.COPY_BATCH_SIZE
  const mediaBatches = Array.from({ length: Math.ceil(allReviewMedia.length / mediaBatchSize) }, (_, i) =>
    allReviewMedia.slice(i * mediaBatchSize, (i + 1) * mediaBatchSize)
  )

  for (const batch of mediaBatches) {
    if (batch.length === 0) continue

    try {
      await copyReviewMedia(batch, tx)
    } catch (error) {
      console.error(`❌ Failed to create review media batch:`, error)
    }
  }

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

  const chunkSize = CONFIG.CHUNK_SIZE
  const chunks = Array.from({ length: Math.ceil(processedProducts.length / chunkSize) }, (_, i) =>
    processedProducts.slice(i * chunkSize, (i + 1) * chunkSize)
  )

  for (const chunk of chunks) {
    try {
      console.log(`🔄 Processing chunk of ${chunk.length} products...`)

      // Validation: Kiểm tra trùng lặp trong database
      const productNames = chunk.map((p) => p.shopeeData.title)
      const existingProducts = await tx.product.findMany({
        where: {
          name: { in: productNames },
          deletedAt: null
        },
        select: { id: true, name: true }
      })

      const existingProductNames = new Set(existingProducts.map((p) => p.name))
      const duplicateProducts = chunk.filter((p) => existingProductNames.has(p.shopeeData.title))

      if (duplicateProducts.length > 0) {
        console.warn(
          `⚠️ Found ${duplicateProducts.length} duplicate products, skipping:`,
          duplicateProducts.map((p) => p.shopeeData.title).slice(0, 5)
        )
        chunk.splice(0, duplicateProducts.length)
      }

      if (chunk.length === 0) {
        console.log('✅ No valid products to create in this chunk')
        continue
      }

      const now = new Date()
      const productsData = chunk.map((processed) => ({
        name: processed.shopeeData.title,
        description: processed.shopeeData['Product Description'] || '',
        basePrice: processed.shopeeData.final_price,
        virtualPrice: processed.shopeeData.initial_price,
        brandId: processed.brandId,
        images: processed.validImages,
        variants: processed.variants,
        specifications: processed.specifications,
        createdById: creatorUserId,
        publishedAt: processed.shopeeData.is_available ? now : null,
        createdAt: now,
        updatedAt: now
      }))

      // Validation: Kiểm tra dữ liệu trước khi tạo
      const validProductsData = productsData.filter((product) => {
        if (!product.name?.trim()) {
          console.warn(`⚠️ Product missing name, skipping`)
          return false
        }
        if (product.basePrice <= 0) {
          console.warn(`⚠️ Product ${product.name} has invalid price: ${product.basePrice}, skipping`)
          return false
        }
        if (!product.brandId) {
          console.warn(`⚠️ Product ${product.name} missing brandId, skipping`)
          return false
        }
        if (!product.images?.length) {
          console.warn(`⚠️ Product ${product.name} missing images, skipping`)
          return false
        }
        return true
      })

      if (validProductsData.length === 0) {
        console.log('✅ No valid products to create in this chunk after validation')
        continue
      }

      const productIds = await copyProducts(validProductsData, tx)

      // Tạo SKUs với validation
      const allSkusData: Array<{
        value: string
        price: number
        stock: number
        image: string
        productId: string
        createdById: string
        createdAt: Date
        updatedAt: Date
      }> = []

      for (let i = 0; i < chunk.length; i++) {
        const processed = chunk[i]
        const productId = productIds[i]

        if (!productId) continue

        // Validation: Kiểm tra SKUs trước khi tạo
        const skus = processed.skus.filter((sku) => {
          if (!sku.value?.trim()) {
            console.warn(`⚠️ SKU missing value for product ${processed.shopeeData.title}, skipping`)
            return false
          }
          if (sku.price <= 0) {
            console.warn(`⚠️ SKU ${sku.value} has invalid price: ${sku.price}, skipping`)
            return false
          }
          if (sku.stock < 0) {
            console.warn(`⚠️ SKU ${sku.value} has invalid stock: ${sku.stock}, skipping`)
            return false
          }
          return true
        })

        const skusData = skus.map((sku) => ({
          ...sku,
          productId,
          createdById: creatorUserId,
          createdAt: now,
          updatedAt: now
        }))

        allSkusData.push(...skusData)
      }

      // Tạo SKUs theo batch
      const skuCopyBatchSize = CONFIG.SKU_BATCH_SIZE
      const skuCopyChunks = Array.from({ length: Math.ceil(allSkusData.length / skuCopyBatchSize) }, (_, i) =>
        allSkusData.slice(i * skuCopyBatchSize, (i + 1) * skuCopyBatchSize)
      )

      for (const skuChunk of skuCopyChunks) {
        if (skuChunk.length > 0) {
          await copySKUs(skuChunk, tx)
        }
      }

      // Tạo translations
      const translationsData = chunk.map((processed, index) => ({
        productId: productIds[index],
        languageId: CONFIG.VIETNAMESE_LANGUAGE_ID,
        name: processed.shopeeData.title,
        description: processed.shopeeData['Product Description'] || '',
        createdById: creatorUserId,
        createdAt: now,
        updatedAt: now
      }))

      if (translationsData.length) {
        await copyProductTranslations(translationsData, tx)
      }

      successCount += chunk.length
      console.log(`✅ Successfully processed ${chunk.length} products`)
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

      // Xóa reviews trước để tránh foreign key constraint
      const productIdsToDelete = productsToDelete.map((p) => p.id)
      console.log(`🗑️ Deleting reviews for ${productIdsToDelete.length} products...`)

      // Xóa review media trước
      await prisma.reviewMedia.deleteMany({
        where: {
          review: {
            productId: { in: productIdsToDelete }
          }
        }
      })

      // Xóa reviews
      await prisma.review.deleteMany({
        where: {
          productId: { in: productIdsToDelete }
        }
      })

      // Xóa SKUs
      await prisma.sKU.deleteMany({
        where: {
          productId: { in: productIdsToDelete }
        }
      })

      // Xóa product translations
      await prisma.productTranslation.deleteMany({
        where: {
          productId: { in: productIdsToDelete }
        }
      })

      // Cuối cùng xóa products
      await prisma.product.deleteMany({
        where: { id: { in: productIdsToDelete } }
      })

      console.log(`✅ Deleted ${productsToDelete.length} outdated products and related data`)
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
