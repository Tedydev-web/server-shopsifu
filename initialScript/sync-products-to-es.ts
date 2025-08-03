import { NestFactory } from '@nestjs/core'
import { AppModule } from '../src/app.module'
import { SearchSyncService } from '../src/shared/services/search-sync.service'
import { PrismaService } from '../src/shared/services/prisma.service'
import { ElasticsearchService } from '../src/shared/services/elasticsearch.service'
import { Logger } from '@nestjs/common'

async function bootstrap() {
  const app = await NestFactory.createApplicationContext(AppModule)
  const logger = new Logger('SyncProductsScript')
  const searchSyncService = app.get(SearchSyncService)
  const prismaService = app.get(PrismaService)
  const elasticsearchService = app.get(ElasticsearchService)

  try {
    logger.log('🚀 Bắt đầu sync tất cả sản phẩm lên Elasticsearch...')

    // Lấy tất cả sản phẩm từ PostgreSQL
    const products = await prismaService.product.findMany({
      where: { deletedAt: null },
      include: {
        skus: {
          where: { deletedAt: null }
        },
        brand: true,
        categories: {
          where: { deletedAt: null }
        }
      }
    })

    logger.log(`📊 Tìm thấy ${products.length} sản phẩm cần sync`)

    if (products.length === 0) {
      logger.warn('❌ Không có sản phẩm nào để sync')
      return
    }

    // Chuyển đổi thành ES documents
    const allEsDocuments: any[] = []

    for (const product of products) {
      if (product.skus.length > 0) {
        for (const sku of product.skus) {
          // Parse attributes từ variants và specifications
          const attrs: Array<{ attrName: string; attrValue: string }> = []

          // Parse từ variants (nếu có)
          if (product.variants && Array.isArray(product.variants)) {
            for (const variant of product.variants) {
              if (variant.value && variant.options && Array.isArray(variant.options)) {
                for (const option of variant.options) {
                  attrs.push({
                    attrName: variant.value,
                    attrValue: option
                  })
                }
              }
            }
          }

          // Parse từ specifications (nếu có)
          if (product.specifications && Array.isArray(product.specifications)) {
            for (const spec of product.specifications) {
              if (spec.name && spec.value) {
                attrs.push({
                  attrName: spec.name,
                  attrValue: spec.value
                })
              }
            }
          }

          const esDocument = {
            skuId: sku.id,
            productId: product.id,
            skuValue: sku.value,
            skuPrice: sku.price,
            skuStock: sku.stock,
            skuImage: sku.image,
            productName: product.name,
            productDescription: product.description,
            productImages: product.images,
            brandId: product.brandId,
            brandName: product.brand?.name || '',
            categoryIds: product.categories.map((cat: any) => cat.id),
            categoryNames: product.categories.map((cat: any) => cat.name),
            specifications: product.specifications,
            variants: product.variants,
            attrs,
            createdAt: product.createdAt,
            updatedAt: product.updatedAt
          }

          allEsDocuments.push(esDocument)
        }
      }
    }

    logger.log(`📝 Đã tạo ${allEsDocuments.length} ES documents`)

    if (allEsDocuments.length > 0) {
      // Bulk index lên Elasticsearch
      const result = await elasticsearchService.bulkIndex('products', allEsDocuments, 'skuId')

      if (result?.errors) {
        logger.error(
          '❌ Có lỗi trong quá trình bulk index:',
          result.items.filter((item: any) => item.index?.error)
        )
      } else {
        logger.log(`✅ Successfully synced ${allEsDocuments.length} SKUs for ${products.length} products`)
      }
    } else {
      logger.warn('❌ Không có SKUs nào để sync')
    }
  } catch (error) {
    logger.error('❌ Sync failed:', error)
  } finally {
    await app.close()
  }
}

bootstrap()
