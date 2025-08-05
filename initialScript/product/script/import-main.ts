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
import { NestFactory } from '@nestjs/core'
import { AppModule } from '../../../src/app.module'
import { SearchSyncService } from '../../../src/shared/services/search-sync.service'

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
      logger.warn(`⚠️ No categories found for product: ${product.title}`)
    }

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

    // SKUs - Tạo SKUs dựa trên variants và product_variation thực tế
    const skus: Array<{ value: string; price: number; stock: number; image: string }> = []

    // Nếu có variants, tạo SKU cho mỗi option
    if (variants.length > 0) {
      variants.forEach((variant) => {
        variant.options.forEach((option) => {
          skus.push({
            value: option,
            price: product.final_price,
            stock: product.stock,
            image: product.image[0] || ''
          })
        })
      })
    } else if (product.product_variation && product.product_variation.length > 0) {
      // Fallback: sử dụng product_variation nếu không có variants
      product.product_variation.forEach((pv) => {
        if (pv.value) {
          skus.push({
            value: pv.value,
            price: product.final_price,
            stock: product.stock,
            image: product.image[0] || ''
          })
        }
      })
    }

    // Nếu vẫn không có SKU nào, tạo SKU mặc định
    if (skus.length === 0) {
      skus.push({
        value: 'Mặc định',
        price: product.final_price,
        stock: product.stock,
        image: product.image[0] || ''
      })
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

    // Metadata - Lưu thông tin bổ sung
    const metadata = {
      url: product.url,
      favorite: product.favorite,
      sold: product.sold,
      seller_products: product.seller_products,
      seller_followers: product.seller_followers,
      seller_rating: product.seller_rating,
      seller_chat_time_reply: product.seller_chat_time_reply,
      seller_chats_responded_percentage: product.seller_chats_responded_percentage,
      seller_joined_date: product.seller_joined_date,
      shop_url: product.shop_url,
      flash_sale: product.flash_sale,
      flash_sale_time: product.flash_sale_time,
      vouchers: product.vouchers,
      gmv_cal: product.gmv_cal,
      domain: product.domain,
      category_url: product.category_url
    }

    return {
      shopeeData: product,
      brandId,
      categoryIds,
      sellerId: sellerMap.get(product.seller_id) || '',
      validImages: product.image.filter((img) => img?.startsWith('http') && img?.length > 0 && !img?.includes('.mp4')),
      validVideos: product.video?.filter((vid) => vid?.startsWith('http') && vid?.includes('.mp4')) || [],
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

    logger.log(`✅ Imported ${successCount} vouchers, failed: ${failCount}`)
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
        logger.warn(`⚠️ Failed to connect product to categories: ${p.shopeeData.title} - ${error}`)
        failedCount++
      }
    }
  }

  logger.log(`✅ Connected ${connectedCount} products to categories, failed: ${failedCount}`)

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
