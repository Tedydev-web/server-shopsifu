import { PrismaClient } from '@prisma/client'
import { NestFactory } from '@nestjs/core'
import { AppModule } from '../../../src/app.module'
import { SearchSyncService } from '../../../src/shared/services/search-sync.service'
import { Logger } from '@nestjs/common'
import { Client } from '@elastic/elasticsearch'

const prisma = new PrismaClient()
const logger = new Logger('SyncToElasticsearch')

// Cấu hình Elasticsearch
const ES_CONFIG = {
  node: 'http://localhost:9200',
  indexName: 'products'
}

/**
 * Clean Elasticsearch index trước khi sync
 * Xóa tất cả documents cũ để tránh trùng lặp
 */
async function cleanElasticsearchIndex(): Promise<void> {
  const client = new Client({ node: ES_CONFIG.node })

  try {
    logger.log('🧹 Bắt đầu clean Elasticsearch index...')

    // Kiểm tra kết nối
    const info = await client.info()
    logger.log(`✅ Kết nối ES thành công - Version: ${info.version.number}`)

    // Kiểm tra index có tồn tại không
    const indexExists = await client.indices.exists({ index: ES_CONFIG.indexName })

    if (indexExists) {
      // Đếm documents hiện tại
      const count = await client.count({ index: ES_CONFIG.indexName })
      logger.log(`📊 Index ${ES_CONFIG.indexName} có ${count.count} documents`)

      if (count.count > 0) {
        logger.log(`🗑️  Đang xóa ${count.count} documents cũ...`)

        // Xóa tất cả documents
        const deleteResult = await client.deleteByQuery({
          index: ES_CONFIG.indexName,
          body: {
            query: {
              match_all: {}
            }
          }
        })

        logger.log(`✅ Đã xóa ${deleteResult.deleted} documents`)

        // Tùy chọn xóa index hoàn toàn để tạo mới
        logger.log('🔄 Đang xóa index để tạo mới...')
        await client.indices.delete({ index: ES_CONFIG.indexName })
        logger.log(`✅ Đã xóa index ${ES_CONFIG.indexName}`)
      } else {
        logger.log(`✅ Index ${ES_CONFIG.indexName} đã trống`)
      }
    } else {
      logger.log(`ℹ️  Index ${ES_CONFIG.indexName} chưa tồn tại`)
    }

    logger.log('🧹 Clean Elasticsearch hoàn thành!')
  } catch (error) {
    logger.error('❌ Lỗi khi clean Elasticsearch:', error)
    throw error
  } finally {
    await client.close()
  }
}

/**
 * Sync tất cả products đã import lên Elasticsearch
 * Sử dụng cơ chế batch processing và NestJS application context
 */
async function syncAllProductsToElasticsearch(): Promise<void> {
  let app: any = null

  try {
    logger.log('🚀 Bắt đầu sync tất cả products lên Elasticsearch...')

    // Bước 1: Clean Elasticsearch trước
    await cleanElasticsearchIndex()

    // Bước 2: Lấy tất cả products đã import (có createdById)
    const products = await prisma.product.findMany({
      where: {
        deletedAt: null,
        createdById: { not: undefined } // Chỉ lấy products được import
      },
      select: {
        id: true,
        name: true
      }
    })

    logger.log(`📦 Tìm thấy ${products.length} products cần sync`)

    if (products.length === 0) {
      logger.warn('⚠️ Không có products nào để sync')
      return
    }

    // Bước 3: Tạo NestJS application context để sử dụng SearchSyncService
    logger.log('🔧 Khởi tạo NestJS application context...')
    app = await NestFactory.createApplicationContext(AppModule)
    const searchSyncService = app.get(SearchSyncService)

    // Bước 4: Sync theo batch để tránh quá tải
    const batchSize = 100
    const batches = Array.from({ length: Math.ceil(products.length / batchSize) }, (_, i) =>
      products.slice(i * batchSize, (i + 1) * batchSize)
    )

    logger.log(`📦 Sẽ sync ${products.length} products trong ${batches.length} batches`)

    let successCount = 0
    let failCount = 0

    // Sync từng batch
    for (let i = 0; i < batches.length; i++) {
      const batch = batches[i]
      const productIds = batch.map((p) => p.id)

      logger.log(`🔄 Đang sync batch ${i + 1}/${batches.length} với ${batch.length} products...`)

      try {
        await searchSyncService.syncProductsBatchToES({
          productIds: productIds,
          action: 'create'
        })

        successCount += batch.length
        logger.log(`✅ Đã sync thành công batch ${i + 1}/${batches.length}`)

        // Log tên các products đã sync
        batch.forEach((product) => {
          logger.log(`  ✅ Queued sync for product: ${product.name}`)
        })
      } catch (error) {
        failCount += batch.length
        logger.error(`❌ Lỗi khi sync batch ${i + 1}/${batches.length}:`, error)
        // Tiếp tục với batch tiếp theo thay vì dừng toàn bộ
      }
    }

    logger.log(`🎉 Sync completed! Success: ${successCount}, Failed: ${failCount}`)
  } catch (error) {
    logger.error('❌ Sync failed:', error)
    throw error
  } finally {
    // Đóng NestJS application context
    if (app) {
      await app.close()
      logger.log('🔌 Đã đóng NestJS application context')
    }

    await prisma.$disconnect()
    logger.log('🔌 Đã ngắt kết nối database')
  }
}

// Chạy script
if (require.main === module) {
  syncAllProductsToElasticsearch()
    .then(() => {
      logger.log('✅ Sync to Elasticsearch completed!')
      process.exit(0)
    })
    .catch((error) => {
      logger.error('❌ Sync to Elasticsearch failed:', error)
      process.exit(1)
    })
}

export { syncAllProductsToElasticsearch, cleanElasticsearchIndex }
