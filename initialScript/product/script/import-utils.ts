// import-utils.ts
import { PrismaClient } from '@prisma/client'
import * as fs from 'fs'
import * as path from 'path'
import { Logger } from '@nestjs/common'

// Config chung
export const CONFIG = {
  BATCH_SIZE: process.env.TEST_MODE === 'true' ? 10 : 15000,
  SKU_BATCH_SIZE: 25000,
  CHUNK_SIZE: 1500,
  PARALLEL_CHUNKS: 12,
  COPY_BATCH_SIZE: 25000,
  DEFAULT_BRAND_NAME: 'No Brand',
  VIETNAMESE_LANGUAGE_ID: 'vi',
  DEFAULT_AVATAR: 'https://shopsifu.s3.ap-southeast-1.amazonaws.com/images/b7de950e-43bd-4f32-b266-d24c080c7a1e.png',
  VIETNAMESE_PHONE_PREFIXES: ['032', '033', '034', '035', '036', '037', '038', '039'],
  MIN_PRICE: 1000,
  MAX_PRICE: 1000000000,
  MIN_STOCK: 0,
  MAX_STOCK: 100000,
  MIN_IMAGE_COUNT: 1,
  MAX_IMAGE_COUNT: 20,
  MAX_TITLE_LENGTH: 500,
  MAX_DESCRIPTION_LENGTH: 5000,
  MAX_SPECIFICATION_COUNT: 50,
  MAX_VARIANT_COUNT: 10,
  MAX_VARIANT_OPTION_COUNT: 20
} as const

// Interface/type chung
export interface ShopeeProduct {
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
  // Thêm các trường bổ sung
  Color?: string | null
  Size?: string | null
  Protection?: string | null
  Delivery?: string | null
}

export interface ProcessedProduct {
  shopeeData: ShopeeProduct
  brandId: string
  categoryIds: string[]
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
  productNumber: number
  productId?: string // Thêm trường productId để map sau khi import
}

// Hàm utility để so sánh dữ liệu thông minh
export function hasDataChanged<T extends Record<string, any>>(
  existingData: T,
  newData: T,
  fieldsToCompare: (keyof T)[]
): boolean {
  for (const field of fieldsToCompare) {
    const existingValue = existingData[field]
    const newValue = newData[field]

    // So sánh arrays
    if (Array.isArray(existingValue) && Array.isArray(newValue)) {
      if (existingValue.length !== newValue.length) return true
      for (let i = 0; i < existingValue.length; i++) {
        if (JSON.stringify(existingValue[i]) !== JSON.stringify(newValue[i])) return true
      }
      continue
    }

    // So sánh objects
    if (typeof existingValue === 'object' && typeof newValue === 'object' && existingValue && newValue) {
      if (JSON.stringify(existingValue) !== JSON.stringify(newValue)) return true
      continue
    }

    // So sánh primitive values
    if (existingValue !== newValue) return true
  }

  return false
}

export interface ValidationResult {
  isValid: boolean
  reason?: string
  issues?: string[]
}

export interface ProductValidationStats {
  total: number
  valid: number
  invalid: number
  issues: { [key: string]: number }
  invalidProducts: Array<{ id: string; title: string; issues: string[] }>
}

// Helper: đọc file JSON
export async function readJsonStream(jsonPath: string): Promise<ShopeeProduct[]> {
  try {
    const fileContent = fs.readFileSync(jsonPath, 'utf8')
    const products: ShopeeProduct[] = JSON.parse(fileContent)
    return products
  } catch (error) {
    console.error('❌ Error reading JSON file:', error)
    return []
  }
}

// Helper: logger
export const logger = new Logger('ProductImport')

// Helper: validate sản phẩm (có thể mở rộng)
export function validateProductEnhanced(product: ShopeeProduct): ValidationResult {
  const issues: string[] = []
  if (!product.id?.trim()) issues.push('Missing ID')
  if (!product.title?.trim()) issues.push('Missing title')
  else if (product.title.length > CONFIG.MAX_TITLE_LENGTH)
    issues.push(`Title too long (${product.title.length} > ${CONFIG.MAX_TITLE_LENGTH})`)
  if (!product.final_price || product.final_price < CONFIG.MIN_PRICE)
    issues.push(`Invalid price: ${product.final_price} < ${CONFIG.MIN_PRICE}`)
  else if (product.final_price > CONFIG.MAX_PRICE)
    issues.push(`Price too high: ${product.final_price} > ${CONFIG.MAX_PRICE}`)
  if (product.stock == null || product.stock < CONFIG.MIN_STOCK)
    issues.push(`Invalid stock: ${product.stock} < ${CONFIG.MIN_STOCK}`)
  else if (product.stock > CONFIG.MAX_STOCK) issues.push(`Stock too high: ${product.stock} > ${CONFIG.MAX_STOCK}`)
  if (!product.breadcrumb || product.breadcrumb.length < 2) issues.push('Invalid breadcrumb structure')
  if (!product.image?.length) issues.push('No images provided')
  else if (product.image.length < CONFIG.MIN_IMAGE_COUNT)
    issues.push(`Too few images: ${product.image.length} < ${CONFIG.MIN_IMAGE_COUNT}`)
  else if (product.image.length > CONFIG.MAX_IMAGE_COUNT)
    issues.push(`Too many images: ${product.image.length} > ${CONFIG.MAX_IMAGE_COUNT}`)
  else {
    const validImages = product.image.filter((img) => img?.startsWith('http'))
    if (validImages.length === 0) issues.push('No valid image URLs')
  }
  if (product['Product Description'] && product['Product Description'].length > CONFIG.MAX_DESCRIPTION_LENGTH)
    issues.push(`Description too long (${product['Product Description'].length} > ${CONFIG.MAX_DESCRIPTION_LENGTH})`)
  if (product['Product Specifications']) {
    if (product['Product Specifications'].length > CONFIG.MAX_SPECIFICATION_COUNT)
      issues.push(
        `Too many specifications: ${product['Product Specifications'].length} > ${CONFIG.MAX_SPECIFICATION_COUNT}`
      )
    for (const spec of product['Product Specifications']) {
      if (!spec.name?.trim() || !spec.value?.trim()) {
        issues.push('Invalid specification format')
        break
      }
    }
  }
  if (product.variations) {
    if (product.variations.length > CONFIG.MAX_VARIANT_COUNT)
      issues.push(`Too many variants: ${product.variations.length} > ${CONFIG.MAX_VARIANT_COUNT}`)
    for (const variant of product.variations) {
      if (!variant.name?.trim()) {
        issues.push('Invalid variant name')
        break
      }
      if (!variant.variations?.length) {
        issues.push('Variant has no options')
        break
      }
      if (variant.variations.length > CONFIG.MAX_VARIANT_OPTION_COUNT) {
        issues.push(`Too many variant options: ${variant.variations.length} > ${CONFIG.MAX_VARIANT_OPTION_COUNT}`)
        break
      }
    }
  }
  return {
    isValid: issues.length === 0,
    reason: issues.length > 0 ? issues[0] : undefined,
    issues
  }
}

// Helper: tạo logger cho từng module
export function createLogger(context: string) {
  return new Logger(context)
}

// Helper: sleep
export function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}
