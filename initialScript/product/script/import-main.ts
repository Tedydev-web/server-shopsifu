import { PrismaClient } from '@prisma/client'
import {
  readJsonStream,
  logger,
  CONFIG,
  ShopeeProduct,
  ProcessedProduct,
  validateProductEnhanced,
  generateEnhancedVariants,
  generateSKUs,
  validateVariantsAndCalculateSKUs,
  generateProductSpecifications,
  generateProductMetadata
} from './import-utils'
import { importBrands } from './import-brands'
import { importCategories } from './import-categories'
import { importUsers } from './import-users'
import { importProducts } from './import-products'
import { importFullAddressesFromGHN } from './import-addresses'
import { importSKUs } from './import-skus'
import { importProductTranslations } from './import-product-translations'
import { importReviews } from './import-reviews'
import { importReviewMedia } from './import-review-media'
import { v4 as uuidv4 } from 'uuid'
import { NestFactory } from '@nestjs/core'
import { AppModule } from '../../../src/app.module'
import { SearchSyncService } from '../../../src/shared/services/search-sync.service'
import { createLanguages } from '../../init/create-languages'

const prisma = new PrismaClient()

// Type definitions cho các mảng dữ liệu import
type OrderData = {
  id: string
  userId: string
  status:
    | 'PENDING_PAYMENT'
    | 'PENDING_PACKAGING'
    | 'PICKUPED'
    | 'PENDING_DELIVERY'
    | 'DELIVERED'
    | 'RETURNED'
    | 'CANCELLED'
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

  // 0. Tạo ngôn ngữ cơ bản trước
  await createLanguages()

  const jsonPath = require('path').join(process.cwd(), 'initialScript', 'product', 'data', 'Shopee-products.json')
  const products: ShopeeProduct[] = await readJsonStream(jsonPath)

  // 1. Validate và lọc sản phẩm hợp lệ
  const validProducts: ShopeeProduct[] = []
  for (const product of products) {
    const validation = validateProductEnhanced(product)
    if (validation.isValid) validProducts.push(product)
  }

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
  const allUsers = await prisma.user.findMany({
    where: { deletedAt: null },
    select: {
      id: true,
      role: { select: { name: true } }
    }
  })
  await importFullAddressesFromGHN(allUsers, creatorUser.id, prisma)

  // 7. Chuẩn bị processedProducts (sử dụng logic đơn giản từ cơ chế cũ)
  const processedProducts: ProcessedProduct[] = validProducts.map((product, idx) => {
    const brandId =
      brandMap.get(product.brand || CONFIG.DEFAULT_BRAND_NAME) || brandMap.get(CONFIG.DEFAULT_BRAND_NAME) || ''
    const categoryNames = product.breadcrumb.slice(1, -1).slice(0, 3)
    const categoryIds = categoryNames.map((name) => categoryMap.get(name)).filter((id) => id) as string[]

    // Nếu không có category nào, thử lấy category đầu tiên
    if (categoryIds.length === 0 && categoryNames.length > 0) {
      const firstCategoryId = categoryMap.get(categoryNames[0])
      if (firstCategoryId) {
        categoryIds.push(firstCategoryId)
      }
    }

    // Log để debug
    if (categoryIds.length === 0) {
    }

    // Variants - Sử dụng logic đơn giản từ cơ chế cũ
    const variants = generateEnhancedVariants(product.variations)

    // Validate variants và tính toán số SKU
    const variantValidation = validateVariantsAndCalculateSKUs(variants)
    if (!variantValidation.isValid) {
    }

    // Specifications - Sử dụng logic đơn giản từ cơ chế cũ
    const specifications = generateProductSpecifications(product)

    // SKUs - Sử dụng logic đúng từ cơ chế cũ
    const validImages = product.image.filter(
      (img) => img?.startsWith('http') && img?.length > 0 && !img?.includes('.mp4')
    )
    const validVideos = product.video?.filter((vid) => vid?.startsWith('http') && vid?.includes('.mp4')) || []
    const skus = generateSKUs(variants, product.final_price, product.stock, [...validImages, ...validVideos])

    // Log thông tin SKU cho debug
    if (skus.length > 1) {
    }

    // Reviews - Chỉ lấy reviews có nội dung
    const reviews = (product.product_ratings || [])
      .filter((r) => r.review && r.review.trim().length > 0) // Chỉ lấy reviews có nội dung
      .map((r) => ({
        clientName: r.customer_name,
        rating: r.rating_stars,
        content: r.review,
        date: r.review_date,
        likes: r.review_likes,
        media: r.review_media
      }))

    // Metadata - Sử dụng logic đơn giản từ cơ chế cũ
    const metadata = generateProductMetadata(product)

    return {
      shopeeData: product,
      brandId,
      categoryIds,
      sellerId: sellerMap.get(product.seller_id) || '',
      validImages,
      validVideos,
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

  // 8.1. Lấy lại productId và map vào processedProducts (sửa để tìm theo tất cả seller IDs)
  const allSellerIds = [...new Set(processedProducts.map((p) => p.sellerId).filter(Boolean))]
  const createdProducts = await prisma.product.findMany({
    where: {
      name: { in: processedProducts.map((p) => p.shopeeData.title) },
      createdById: { in: allSellerIds }
    },
    select: { id: true, name: true, createdById: true }
  })

  // Tạo map từ (name, createdById) -> productId để tìm chính xác
  const nameAndSellerToProductId = new Map(createdProducts.map((p) => [`${p.name}_${p.createdById}`, p.id]))

  processedProducts.forEach((p) => {
    const key = `${p.shopeeData.title}_${p.sellerId}`
    p.productId = nameAndSellerToProductId.get(key)
  })

  // 8.2. Import SKUs cho từng product (sử dụng sellerId thay vì creatorUserId)
  const skusData = processedProducts.flatMap((p) =>
    p.skus.map((sku) => ({
      ...sku,
      productId: p.productId!,
      createdById: p.sellerId || creatorUser.id, // ✅ Sử dụng sellerId thay vì creatorUserId
      createdAt: new Date(),
      updatedAt: new Date()
    }))
  )
  if (skusData.length) await importSKUs(skusData, prisma)

  // 8.3. Import ProductTranslations cho từng product (tiếng Việt) - sử dụng sellerId
  const translationsData = processedProducts.map((p) => ({
    productId: p.productId!,
    languageId: CONFIG.VIETNAMESE_LANGUAGE_ID,
    name: p.shopeeData.title,
    description: p.shopeeData['Product Description'] || '',
    createdById: p.sellerId || creatorUser.id, // ✅ Sử dụng sellerId thay vì creatorUserId
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
  if (ordersData.length) await prisma.order.createMany({ data: ordersData as any, skipDuplicates: true })
  let reviewIds: string[] = []
  if (reviewsData.length) reviewIds = await importReviews(reviewsData, prisma)

  // 8.6. Import review media (chỉ từ review, không import product video vào review)
  const reviewMedias: ReviewMediaData[] = []
  let reviewIdx = 0
  processedProducts.forEach((p) => {
    p.reviews.forEach((review, idx) => {
      if (reviewIds[reviewIdx]) {
        // Import review media từ review
        if (review.media) {
          review.media.forEach((url) => {
            if (url && typeof url === 'string') {
              reviewMedias.push({
                url,
                type: url.endsWith('.mp4') ? 'VIDEO' : 'IMAGE',
                reviewId: reviewIds[reviewIdx],
                createdAt: new Date()
              })
            }
          })
        }
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
        if (voucher && typeof voucher === 'object' && voucher.value && voucher.value > 0) {
          // Chỉ import voucher có giá trị hợp lệ
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
            discountType: voucher.value > 100 ? 'PERCENTAGE' : 'FIX_AMOUNT',
            discountStatus: 'ACTIVE',
            voucherType: 'PRODUCT',
            isPlatform: false,
            displayType: 'PUBLIC',
            discountApplyType: 'SPECIFIC',
            createdById: p.sellerId || creatorUser.id, // ✅ Sử dụng sellerId thay vì creatorUserId
            shopId: p.sellerId || null, // ✅ Thêm shopId để liên kết với shop
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
    let successCount = 0
    let failCount = 0

    for (const voucher of vouchersData) {
      try {
        await prisma.discount.create({
          data: voucher
        })
        successCount++
      } catch (error) {
        logger.warn(`⚠️ Failed to import voucher: ${voucher.code} - ${error}`)
        failCount++
      }
    }
  }

  // 8.8. Import product videos (nếu có) vào product images
  for (const p of processedProducts) {
    if (p.productId && p.validVideos.length > 0) {
      // Thêm videos vào product images
      const product = await prisma.product.findUnique({
        where: { id: p.productId },
        select: { images: true }
      })

      if (product) {
        // Tránh duplicate videos
        const existingVideos = product.images.filter((img) => img.includes('.mp4'))
        const newVideos = p.validVideos.filter((video) => !existingVideos.includes(video))
        const updatedImages = [...product.images, ...newVideos]

        if (newVideos.length > 0) {
          await prisma.product.update({
            where: { id: p.productId },
            data: { images: updatedImages }
          })
          logger.log(`📹 Added ${newVideos.length} videos to product: ${p.shopeeData.title}`)
        }
      }
    }
  }

  // 8.9. Gán product vào category (sử dụng connect thay vì createMany)
  let connectedCount = 0
  let failedCount = 0

  for (const p of processedProducts) {
    if (p.productId && p.categoryIds.length > 0) {
      try {
        await prisma.product.update({
          where: { id: p.productId },
          data: {
            categories: {
              connect: p.categoryIds.map((categoryId) => ({ id: categoryId }))
            }
          }
        })
        connectedCount++
      } catch (error) {
        failedCount++
      }
    }
  }

  // 8.10. Sync products với Elasticsearch
  if (processedProducts.length > 0) {
    logger.log('🔄 Syncing products với Elasticsearch...')

    try {
      // Tạo NestJS application context
      const app = await NestFactory.createApplicationContext(AppModule)
      const searchSyncService = app.get(SearchSyncService)

      // Lấy tất cả product IDs đã tạo
      const productIds = processedProducts.map((p) => p.productId).filter((id) => id) as string[]

      if (productIds.length > 0) {
        // Sync theo batch để tránh quá tải
        const batchSize = 100
        const batches = Array.from({ length: Math.ceil(productIds.length / batchSize) }, (_, i) =>
          productIds.slice(i * batchSize, (i + 1) * batchSize)
        )

        logger.log(`📦 Sẽ sync ${productIds.length} products trong ${batches.length} batches`)

        let syncSuccessCount = 0
        let syncFailCount = 0

        for (let i = 0; i < batches.length; i++) {
          const batch = batches[i]

          try {
            await searchSyncService.syncProductsBatchToES({
              productIds: batch,
              action: 'create'
            })
            syncSuccessCount += batch.length
            logger.log(`✅ Đã sync thành công batch ${i + 1}/${batches.length}`)

            // Thêm delay giữa các batch để tránh quá tải
            if (i < batches.length - 1) {
              await new Promise((resolve) => setTimeout(resolve, 1000)) // Delay 1 giây
            }
          } catch (error) {
            syncFailCount += batch.length
            logger.error(`❌ Lỗi khi sync batch ${i + 1}/${batches.length}:`, error)
          }
        }

        logger.log(`🎉 Elasticsearch sync completed! Success: ${syncSuccessCount}, Failed: ${syncFailCount}`)
      }

      await app.close()
    } catch (error) {
      logger.error('❌ Lỗi khi sync với Elasticsearch:', error)
      // Không throw error để không làm fail toàn bộ import
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
