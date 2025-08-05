import { PrismaClient } from '@prisma/client'
import {
  readJsonStream,
  logger,
  CONFIG,
  ShopeeProduct,
  ProcessedProduct,
  validateProductEnhanced
} from './import-utils'
import { importBrands } from './import-brands'
import { importCategories } from './import-categories'
import { importUsers } from './import-users'
import { importProducts } from './import-products'
import { importAddresses } from './import-addresses'
import { importSKUs } from './import-skus'
import { importProductTranslations } from './import-product-translations'
import { importReviews } from './import-reviews'
import { importReviewMedia } from './import-review-media'
import { v4 as uuidv4 } from 'uuid'

const prisma = new PrismaClient()

// Type definitions cho các mảng dữ liệu import
type OrderData = {
  id: string
  userId: string
  status: 'PENDING_PAYMENT' | 'PENDING_PICKUP' | 'PENDING_DELIVERY' | 'DELIVERED' | 'RETURNED' | 'CANCELLED'
  createdAt: Date
  updatedAt: Date
  receiver: string
  shopId: string
  paymentId: number
}

type ReviewData = {
  rating: number
  content: string
  userId: string
  productId: string
  orderId: string
  createdAt: Date
  updatedAt: Date
}

type ReviewMediaData = {
  url: string
  type: 'IMAGE' | 'VIDEO'
  reviewId: string
  createdAt: Date
}

async function main() {
  logger.log('🚀 Bắt đầu import dữ liệu Shopee...')
  await prisma.$connect()
  const jsonPath = require('path').join(process.cwd(), 'initialScript', 'product', 'data', 'Shopee-products.json')
  const products: ShopeeProduct[] = await readJsonStream(jsonPath)
  logger.log(`📦 Đã load ${products.length} sản phẩm từ file JSON`)

  // 1. Validate và lọc sản phẩm hợp lệ
  const validProducts: ShopeeProduct[] = []
  for (const product of products) {
    const validation = validateProductEnhanced(product)
    if (validation.isValid) validProducts.push(product)
  }
  logger.log(`✅ Có ${validProducts.length} sản phẩm hợp lệ để import`)

  // 2. Import brands
  const creatorUser = await prisma.user.findFirst({ orderBy: { createdAt: 'asc' } })
  if (!creatorUser) throw new Error('Không tìm thấy user tạo dữ liệu!')
  const brandMap = await importBrands(validProducts, creatorUser.id, prisma)

  // 3. Import categories
  const categoryMap = await importCategories(validProducts, creatorUser.id, prisma)

  // 4. Import users (sellers)
  const uniqueSellers = new Map(
    validProducts
      .map((p) => [p.seller_id, p])
      .filter(([_, p]) => (p as ShopeeProduct).seller_id && (p as ShopeeProduct).seller_name) as [
      string,
      ShopeeProduct
    ][]
  )
  const sellerMap = await importUsers(uniqueSellers as Map<string, ShopeeProduct>, 'SELLER', creatorUser.id, prisma)

  // 5. Import users (customers)
  const uniqueCustomers = new Map(
    validProducts
      .flatMap((p) => p.product_ratings?.map((r) => [r.customer_name, r.customer_name]) || [])
      .filter(([name]) => name) as [string, string][]
  )
  const clientMap = await importUsers(uniqueCustomers as Map<string, string>, 'CLIENT', creatorUser.id, prisma)

  // 6. Import addresses cho tất cả users
  const allUsers = await prisma.user.findMany({ where: { deletedAt: null }, select: { id: true } })
  await importAddresses(allUsers, creatorUser.id, prisma)

  // 7. Chuẩn bị processedProducts (tận dụng triệt để mọi trường)
  const processedProducts: ProcessedProduct[] = validProducts.map((product, idx) => {
    const brandId = brandMap.get(product.brand || CONFIG.DEFAULT_BRAND_NAME) || ''
    const categoryNames = product.breadcrumb.slice(1, -1).slice(0, 3)
    const categoryIds = categoryNames.map((name) => categoryMap.get(name)).filter((id) => id) as string[]

    // Variants - Merge cả variations và product_variation
    const variants = (product.variations || []).map((v) => ({
      value: v.name,
      options: v.variations
    }))

    // Nếu có product_variation, merge vào variants
    if (product.product_variation && product.product_variation.length > 0) {
      product.product_variation.forEach((pv) => {
        const existingVariant = variants.find((v) => v.value === pv.name)
        if (existingVariant) {
          if (pv.value && !existingVariant.options.includes(pv.value)) {
            existingVariant.options.push(pv.value)
          }
        } else {
          variants.push({
            value: pv.name,
            options: pv.value ? [pv.value] : []
          })
        }
      })
    }

    // Specifications - Merge cả Product Specifications và các trường bổ sung
    const specifications = (product['Product Specifications'] || []).map((s) => ({
      name: s.name,
      value: s.value
    }))

    // Thêm các trường bổ sung vào specifications
    if (product.Color) {
      specifications.push({ name: 'Màu sắc', value: product.Color })
    }
    if (product.Size) {
      specifications.push({ name: 'Kích thước', value: product.Size })
    }
    if (product.Protection) {
      specifications.push({ name: 'Bảo hành', value: product.Protection })
    }
    if (product.Delivery) {
      specifications.push({ name: 'Giao hàng', value: product.Delivery })
    }

    // SKUs
    const skus = (product.product_variation || []).map((v) => ({
      value: v.name,
      price: product.final_price,
      stock: product.stock,
      image: product.image[0] // hoặc logic chọn ảnh phù hợp
    }))

    // Reviews
    const reviews = (product.product_ratings || []).map((r) => ({
      clientName: r.customer_name,
      rating: r.rating_stars,
      content: r.review,
      date: r.review_date,
      likes: r.review_likes,
      media: r.review_media
    }))

    // Metadata
    const metadata = {
      url: product.url,
      favorite: product.favorite,
      sold: product.sold,
      seller_products: product.seller_products,
      seller_followers: product.seller_followers,
      shop_url: product.shop_url,
      flash_sale: product.flash_sale,
      flash_sale_time: product.flash_sale_time,
      vouchers: product.vouchers,
      gmv_cal: product.gmv_cal
    }

    return {
      shopeeData: product,
      brandId,
      categoryIds,
      sellerId: sellerMap.get(product.seller_id) || '',
      validImages: product.image.filter((img) => img?.startsWith('http')),
      validVideos: product.video?.filter((vid) => vid?.startsWith('http')) || [],
      variants,
      specifications,
      metadata,
      skus,
      reviews,
      productNumber: idx + 1
    }
  })

  // 8. Import products
  const productResult = await importProducts(processedProducts, creatorUser.id, prisma)

  // 8.1. Lấy lại productId và map vào processedProducts
  const createdProducts = await prisma.product.findMany({
    where: { name: { in: processedProducts.map((p) => p.shopeeData.title) }, createdById: creatorUser.id },
    select: { id: true, name: true }
  })
  const nameToProductId = new Map(createdProducts.map((p) => [p.name, p.id]))
  processedProducts.forEach((p) => {
    p.productId = nameToProductId.get(p.shopeeData.title)
  })

  // 8.2. Import SKUs cho từng product
  const skusData = processedProducts.flatMap((p) =>
    p.skus.map((sku) => ({
      ...sku,
      productId: p.productId!,
      createdById: creatorUser.id,
      createdAt: new Date(),
      updatedAt: new Date()
    }))
  )
  if (skusData.length) await importSKUs(skusData, prisma)

  // 8.3. Import ProductTranslations cho từng product (tiếng Việt)
  const translationsData = processedProducts.map((p) => ({
    productId: p.productId!,
    languageId: CONFIG.VIETNAMESE_LANGUAGE_ID,
    name: p.shopeeData.title,
    description: p.shopeeData['Product Description'] || '',
    createdById: creatorUser.id,
    createdAt: new Date(),
    updatedAt: new Date()
  }))
  if (translationsData.length) await importProductTranslations(translationsData, prisma)

  // 8.4. Tạo payment giả lập trước (nếu chưa có)
  const existingPayment = await prisma.payment.findFirst({
    where: { status: 'SUCCESS' },
    orderBy: { createdAt: 'desc' }
  })

  const mockPayment =
    existingPayment ||
    (await prisma.payment.create({
      data: {
        status: 'SUCCESS',
        createdAt: new Date(),
        updatedAt: new Date()
      }
    }))

  // 8.5. Sinh order giả lập cho mỗi review, import reviews
  const ordersData: OrderData[] = []
  const reviewsData: ReviewData[] = []
  processedProducts.forEach((p) => {
    p.reviews.forEach((review, idx) => {
      const userId = clientMap.get(review.clientName)
      if (!userId) return // Skip nếu không có userId hợp lệ

      const orderId = uuidv4()
      ordersData.push({
        id: orderId,
        userId,
        status: 'DELIVERED',
        createdAt: new Date(),
        updatedAt: new Date(),
        receiver: JSON.stringify({ name: review.clientName || 'Khách', phone: '', address: '' }),
        shopId: p.sellerId,
        paymentId: mockPayment.id // Sử dụng paymentId thực tế
      })
      reviewsData.push({
        rating: review.rating,
        content: review.content,
        userId,
        productId: p.productId!,
        orderId,
        createdAt: new Date(),
        updatedAt: new Date()
      })
    })
  })
  if (ordersData.length) await prisma.order.createMany({ data: ordersData, skipDuplicates: true })
  let reviewIds: string[] = []
  if (reviewsData.length) reviewIds = await importReviews(reviewsData, prisma)

  // 8.6. Import review media
  const reviewMedias: ReviewMediaData[] = []
  let reviewIdx = 0
  processedProducts.forEach((p) => {
    p.reviews.forEach((review, idx) => {
      if (review.media && reviewIds[reviewIdx]) {
        // Ensure reviewId exists
        review.media.forEach((url) => {
          if (url && typeof url === 'string') {
            // Validate url is not null/undefined
            reviewMedias.push({
              url,
              type: url.endsWith('.mp4') ? 'VIDEO' : 'IMAGE',
              reviewId: reviewIds[reviewIdx],
              createdAt: new Date()
            })
          }
        })
      }
      reviewIdx++
    })
  })
  if (reviewMedias.length) await importReviewMedia(reviewMedias, prisma)

  // 8.7. Import vouchers nếu có
  const vouchersData: any[] = []
  processedProducts.forEach((p) => {
    if (p.shopeeData.vouchers && Array.isArray(p.shopeeData.vouchers)) {
      p.shopeeData.vouchers.forEach((voucher: any) => {
        if (voucher && typeof voucher === 'object') {
          vouchersData.push({
            name: voucher.name || `Voucher ${p.shopeeData.title}`,
            description: voucher.description || '',
            value: voucher.value || 0,
            code: voucher.code || `VOUCHER_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
            startDate: new Date(),
            endDate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 ngày
            minOrderValue: voucher.minOrderValue || 0,
            maxUses: voucher.maxUses || 100,
            maxUsesPerUser: voucher.maxUsesPerUser || 1,
            discountType: 'PERCENTAGE',
            discountStatus: 'ACTIVE',
            voucherType: 'PRODUCT',
            isPlatform: false,
            displayType: 'PUBLIC',
            discountApplyType: 'SPECIFIC',
            createdById: creatorUser.id,
            createdAt: new Date(),
            updatedAt: new Date(),
            products: {
              connect: p.productId ? [{ id: p.productId }] : []
            }
          })
        }
      })
    }
  })

  if (vouchersData.length > 0) {
    logger.log(`📦 Importing ${vouchersData.length} vouchers...`)
    for (const voucher of vouchersData) {
      try {
        await prisma.discount.create({
          data: voucher
        })
      } catch (error) {
        logger.warn(`⚠️ Failed to import voucher: ${voucher.code}`)
      }
    }
  }

  // 8.8. Gán product vào category (sử dụng connect thay vì createMany)
  for (const p of processedProducts) {
    if (p.productId && p.categoryIds.length > 0) {
      await prisma.product.update({
        where: { id: p.productId },
        data: {
          categories: {
            connect: p.categoryIds.map((categoryId) => ({ id: categoryId }))
          }
        }
      })
    }
  }

  logger.log('🎉 Import hoàn tất!')
  await prisma.$disconnect()
}

if (require.main === module) {
  main().catch((err) => {
    logger.error('❌ Import thất bại:', err)
    process.exit(1)
  })
}
