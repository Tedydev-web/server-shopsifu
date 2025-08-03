import { Injectable, Logger } from '@nestjs/common'
import { PrismaService } from './prisma.service'
import { ElasticsearchService } from './elasticsearch.service'
import { ConfigService } from '@nestjs/config'
import { EsProductDocumentType, SyncProductJobType, SyncProductsBatchJobType } from '../models/search-sync.model'
import { ES_INDEX_PRODUCTS } from '../constants/search-sync.constant'

@Injectable()
export class SearchSyncService {
  private readonly logger = new Logger(SearchSyncService.name)

  constructor(
    private readonly prisma: PrismaService,
    private readonly es: ElasticsearchService,
    private readonly configService: ConfigService
  ) {}

  /**
   * Đồng bộ một sản phẩm lên Elasticsearch
   */
  async syncProductToES(jobData: SyncProductJobType): Promise<void> {
    const { productId, action } = jobData

    this.logger.log(`🔄 Starting sync for product ${productId} with action: ${action}`)

    try {
      if (action === 'delete') {
        await this.deleteProductFromES(productId)
        return
      }

      // Lấy dữ liệu sản phẩm từ PostgreSQL
      const product = await this.prisma.product.findUnique({
        where: { id: productId },
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

      if (!product) {
        this.logger.warn(`Product ${productId} not found, skipping sync`)
        return
      }

      if (!product.skus.length) {
        this.logger.warn(`Product ${productId} has no SKUs, skipping sync`)
        return
      }

      // Chuyển đổi thành ES documents
      const esDocuments = this.transformProductToEsDocuments(product)

      // Bulk index lên Elasticsearch
      await this.es.bulkIndex(ES_INDEX_PRODUCTS, esDocuments, 'skuId')

      this.logger.log(`✅ Successfully synced ${esDocuments.length} SKUs for product ${productId}`)
    } catch (error) {
      this.logger.error(`❌ Failed to sync product ${productId}:`, error)
      throw error
    }
  }

  /**
   * Đồng bộ nhiều sản phẩm lên Elasticsearch (batch)
   */
  async syncProductsBatchToES(jobData: SyncProductsBatchJobType): Promise<void> {
    const { productIds, action } = jobData

    this.logger.log(`🔄 Starting batch sync for ${productIds.length} products with action: ${action}`)

    try {
      if (action === 'delete') {
        await this.deleteProductsBatchFromES(productIds)
        return
      }

      // Lấy dữ liệu nhiều sản phẩm từ PostgreSQL
      const products = await this.prisma.product.findMany({
        where: {
          id: { in: productIds },
          deletedAt: null
        },
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

      if (!products.length) {
        this.logger.warn('No products found for batch sync')
        return
      }

      // Chuyển đổi thành ES documents
      const allEsDocuments: EsProductDocumentType[] = []

      for (const product of products) {
        if (product.skus.length > 0) {
          const esDocuments = this.transformProductToEsDocuments(product)
          allEsDocuments.push(...esDocuments)
        }
      }

      if (allEsDocuments.length > 0) {
        // Bulk index lên Elasticsearch
        await this.es.bulkIndex(ES_INDEX_PRODUCTS, allEsDocuments, 'skuId')
        this.logger.log(`✅ Successfully synced ${allEsDocuments.length} SKUs for ${products.length} products`)
      } else {
        this.logger.warn('No SKUs found for batch sync')
      }
    } catch (error) {
      this.logger.error(`❌ Failed to batch sync products:`, error)
      throw error
    }
  }

  /**
   * Xóa sản phẩm khỏi Elasticsearch
   */
  private async deleteProductFromES(productId: string): Promise<void> {
    try {
      // Lấy tất cả SKU IDs của sản phẩm
      const skus = await this.prisma.sKU.findMany({
        where: {
          productId,
          deletedAt: null
        },
        select: { id: true }
      })

      if (!skus.length) {
        this.logger.warn(`No SKUs found for product ${productId} to delete`)
        return
      }

      // Xóa từng SKU document khỏi ES
      for (const sku of skus) {
        await this.es.deleteById(ES_INDEX_PRODUCTS, sku.id)
      }

      this.logger.log(`✅ Successfully deleted ${skus.length} SKUs for product ${productId} from ES`)
    } catch (error) {
      this.logger.error(`❌ Failed to delete product ${productId} from ES:`, error)
      throw error
    }
  }

  /**
   * Xóa nhiều sản phẩm khỏi Elasticsearch (batch)
   */
  private async deleteProductsBatchFromES(productIds: string[]): Promise<void> {
    try {
      // Lấy tất cả SKU IDs của các sản phẩm
      const skus = await this.prisma.sKU.findMany({
        where: {
          productId: { in: productIds },
          deletedAt: null
        },
        select: { id: true }
      })

      if (!skus.length) {
        this.logger.warn('No SKUs found for batch delete')
        return
      }

      // Xóa từng SKU document khỏi ES
      for (const sku of skus) {
        await this.es.deleteById(ES_INDEX_PRODUCTS, sku.id)
      }

      this.logger.log(`✅ Successfully deleted ${skus.length} SKUs for ${productIds.length} products from ES`)
    } catch (error) {
      this.logger.error(`❌ Failed to batch delete products from ES:`, error)
      throw error
    }
  }

  /**
   * Chuyển đổi Product thành ES documents
   */
  private transformProductToEsDocuments(product: any): EsProductDocumentType[] {
    const esDocuments: EsProductDocumentType[] = []

    for (const sku of product.skus) {
      // Parse attributes từ variants và specifications
      const attrs = this.parseAttributesFromProduct(product, sku)

      const esDocument: EsProductDocumentType = {
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

      esDocuments.push(esDocument)
    }

    return esDocuments
  }

  /**
   * Parse attributes từ variants và specifications
   */
  private parseAttributesFromProduct(product: any, sku: any): Array<{ attrName: string; attrValue: string }> {
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

    return attrs
  }

  /**
   * Tìm kiếm sản phẩm trong Elasticsearch
   */
  async searchProducts(
    query: any,
    options: {
      size?: number
      from?: number
      sort?: any[]
    } = {}
  ) {
    try {
      const result = await this.es.search(ES_INDEX_PRODUCTS, query, options)
      return result
    } catch (error) {
      this.logger.error('Search products failed:', error)
      throw error
    }
  }
}
