import { Injectable, Logger } from '@nestjs/common'
import { PrismaService } from './prisma.service'
import { ElasticsearchService } from './elasticsearch.service'
import { ConfigService } from '@nestjs/config'
import { Queue } from 'bullmq'
import { EsProductDocumentType, SyncProductJobType, SyncProductsBatchJobType } from '../models/search-sync.model'
import {
  SEARCH_SYNC_QUEUE_NAME,
  SYNC_PRODUCT_JOB,
  SYNC_PRODUCTS_BATCH_JOB,
  DELETE_PRODUCT_JOB,
  JOB_OPTIONS
} from '../constants/search-sync.constant'

@Injectable()
export class SearchSyncService {
  private readonly logger = new Logger(SearchSyncService.name)
  public readonly queue: Queue

  constructor(
    private readonly prisma: PrismaService,
    private readonly es: ElasticsearchService,
    private readonly configService: ConfigService
  ) {
    const password = this.configService.get<string>('redis.password')
    const requireAuth = Boolean(this.configService.get('redis.requireAuth'))
    const isPasswordProvided = requireAuth && typeof password === 'string' && password.trim().length > 0
    this.queue = new Queue(SEARCH_SYNC_QUEUE_NAME, {
      connection: {
        host: this.configService.get('redis.host'),
        port: this.configService.get('redis.port'),
        ...(isPasswordProvided ? { password } : {})
      },
      prefix: 'shopsifu:bull'
    })
  }

  /**
   * Thêm job đồng bộ một sản phẩm
   */
  async addSyncProductJob(productId: string, action: 'create' | 'update' | 'delete' = 'create') {
    const jobData: SyncProductJobType = { productId, action }

    try {
      await this.queue.add(SYNC_PRODUCT_JOB, jobData, {
        attempts: JOB_OPTIONS.ATTEMPTS,
        backoff: JOB_OPTIONS.BACKOFF,
        removeOnComplete: JOB_OPTIONS.REMOVE_ON_COMPLETE,
        removeOnFail: JOB_OPTIONS.REMOVE_ON_FAIL
      })
      this.logger.log(`Added sync job for product ${productId} with action: ${action}`)
    } catch (error) {
      this.logger.error(`Failed to add sync job for product ${productId}:`, error)
      throw error
    }
  }

  /**
   * Thêm job đồng bộ nhiều sản phẩm (batch)
   */
  async addSyncProductsBatchJob(productIds: string[], action: 'create' | 'update' | 'delete' = 'create') {
    const jobData: SyncProductsBatchJobType = { productIds, action }

    try {
      await this.queue.add(SYNC_PRODUCTS_BATCH_JOB, jobData, {
        attempts: JOB_OPTIONS.ATTEMPTS,
        backoff: JOB_OPTIONS.BACKOFF,
        removeOnComplete: JOB_OPTIONS.REMOVE_ON_COMPLETE,
        removeOnFail: JOB_OPTIONS.REMOVE_ON_FAIL
      })
      this.logger.log(`Added batch sync job for ${productIds.length} products with action: ${action}`)
    } catch (error) {
      this.logger.error(`Failed to add batch sync job:`, error)
      throw error
    }
  }

  /**
   * Thêm job xóa sản phẩm khỏi ES
   */
  async addDeleteProductJob(productId: string) {
    try {
      await this.queue.add(
        DELETE_PRODUCT_JOB,
        { productId },
        {
          attempts: JOB_OPTIONS.ATTEMPTS,
          backoff: JOB_OPTIONS.BACKOFF,
          removeOnComplete: JOB_OPTIONS.REMOVE_ON_COMPLETE,
          removeOnFail: JOB_OPTIONS.REMOVE_ON_FAIL
        }
      )
      this.logger.log(`Added delete job for product ${productId}`)
    } catch (error) {
      this.logger.error(`Failed to add delete job for product ${productId}:`, error)
      throw error
    }
  }

  /**
   * Lấy thông tin queue
   */
  async getQueueInfo() {
    try {
      const [waiting, active, completed, failed] = await Promise.all([
        this.queue.getWaiting(),
        this.queue.getActive(),
        this.queue.getCompleted(),
        this.queue.getFailed()
      ])

      return {
        waiting: waiting.length,
        active: active.length,
        completed: completed.length,
        failed: failed.length
      }
    } catch (error) {
      this.logger.error('Failed to get queue info:', error)
      throw error
    }
  }

  /**
   * Xóa tất cả jobs trong queue
   */
  async clearQueue() {
    try {
      await Promise.all([
        this.queue.clean(0, 0, 'completed'),
        this.queue.clean(0, 0, 'failed'),
        this.queue.clean(0, 0, 'waiting')
      ])
      this.logger.log('Cleared search sync queue')
    } catch (error) {
      this.logger.error('Failed to clear queue:', error)
      throw error
    }
  }

  /**
   * Pause queue
   */
  async pauseQueue() {
    try {
      await this.queue.pause()
      this.logger.log('Paused search sync queue')
    } catch (error) {
      this.logger.error('Failed to pause queue:', error)
      throw error
    }
  }

  /**
   * Resume queue
   */
  async resumeQueue() {
    try {
      await this.queue.resume()
      this.logger.log('Resumed search sync queue')
    } catch (error) {
      this.logger.error('Failed to resume queue:', error)
      throw error
    }
  }

  /**
   * Đồng bộ một sản phẩm lên Elasticsearch
   */
  async syncProductToES(jobData: SyncProductJobType): Promise<void> {
    const { productId, action } = jobData

    this.logger.log(`Starting sync for product ${productId} with action: ${action}`)

    try {
      if (action === 'delete') {
        await this.deleteProductFromES(productId)
        return
      }

      const product = await this.getProductWithRelations(productId)
      if (!product || !product.skus.length) {
        this.logger.warn(`Product ${productId} not found or has no SKUs, skipping sync`)
        return
      }

      const esDocuments = this.transformProductToEsDocuments(product)
      await this.es.bulkIndex(
        this.configService.get('elasticsearch.index.products') || 'products',
        esDocuments,
        'skuId'
      )

      this.logger.log(`Successfully synced ${esDocuments.length} SKUs for product ${productId}`)
    } catch (error) {
      this.logger.error(`Failed to sync product ${productId}:`, error)
      throw error
    }
  }

  /**
   * Đồng bộ nhiều sản phẩm lên Elasticsearch (batch)
   */
  async syncProductsBatchToES(jobData: SyncProductsBatchJobType): Promise<void> {
    const { productIds, action } = jobData

    this.logger.log(`Starting batch sync for ${productIds.length} products with action: ${action}`)

    try {
      if (action === 'delete') {
        await this.deleteProductsBatchFromES(productIds)
        return
      }

      const products = await this.getProductsWithRelations(productIds)
      if (!products.length) {
        this.logger.warn('No products found for batch sync')
        return
      }

      const allEsDocuments: EsProductDocumentType[] = []
      for (const product of products) {
        if (product.skus.length > 0) {
          const esDocuments = this.transformProductToEsDocuments(product)
          allEsDocuments.push(...esDocuments)
        }
      }

      if (allEsDocuments.length > 0) {
        await this.es.bulkIndex(
          this.configService.get('elasticsearch.index.products') || 'products',
          allEsDocuments,
          'skuId'
        )
        this.logger.log(`Successfully synced ${allEsDocuments.length} SKUs for ${products.length} products`)
      } else {
        this.logger.warn('No SKUs found for batch sync')
      }
    } catch (error) {
      this.logger.error(`Failed to batch sync products:`, error)
      throw error
    }
  }

  /**
   * Lấy product với relations
   */
  private async getProductWithRelations(productId: string) {
    return await this.prisma.product.findUnique({
      where: { id: productId },
      include: {
        skus: { where: { deletedAt: null } },
        brand: true,
        categories: { where: { deletedAt: null } }
      }
    })
  }

  /**
   * Lấy products với relations
   */
  private async getProductsWithRelations(productIds: string[]) {
    return await this.prisma.product.findMany({
      where: {
        id: { in: productIds },
        deletedAt: null
      },
      include: {
        skus: { where: { deletedAt: null } },
        brand: true,
        categories: { where: { deletedAt: null } }
      }
    })
  }

  /**
   * Xóa sản phẩm khỏi Elasticsearch
   */
  private async deleteProductFromES(productId: string): Promise<void> {
    try {
      const skus = await this.prisma.sKU.findMany({
        where: { productId, deletedAt: null },
        select: { id: true }
      })

      if (!skus.length) {
        this.logger.warn(`No SKUs found for product ${productId} to delete`)
        return
      }

      for (const sku of skus) {
        await this.es.deleteById(this.configService.get('elasticsearch.index.products') || 'products', sku.id)
      }

      this.logger.log(`Successfully deleted ${skus.length} SKUs for product ${productId} from ES`)
    } catch (error) {
      this.logger.error(`Failed to delete product ${productId} from ES:`, error)
      throw error
    }
  }

  /**
   * Xóa nhiều sản phẩm khỏi Elasticsearch (batch)
   */
  private async deleteProductsBatchFromES(productIds: string[]): Promise<void> {
    try {
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

      for (const sku of skus) {
        await this.es.deleteById(this.configService.get('elasticsearch.index.products') || 'products', sku.id)
      }

      this.logger.log(`Successfully deleted ${skus.length} SKUs for ${productIds.length} products from ES`)
    } catch (error) {
      this.logger.error(`Failed to batch delete products from ES:`, error)
      throw error
    }
  }

  /**
   * Chuyển đổi Product thành ES documents
   */
  private transformProductToEsDocuments(product: any): EsProductDocumentType[] {
    const esDocuments: EsProductDocumentType[] = []

    for (const sku of product.skus) {
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

    // Parse từ variants
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

    // Parse từ specifications
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
}
