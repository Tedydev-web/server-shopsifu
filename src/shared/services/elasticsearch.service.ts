import { Injectable, Logger, OnModuleInit } from '@nestjs/common'
import { Client } from '@elastic/elasticsearch'
import { ConfigService } from '@nestjs/config'

@Injectable()
export class ElasticsearchService implements OnModuleInit {
  private readonly logger = new Logger(ElasticsearchService.name)
  public readonly client: Client

  constructor(private readonly configService: ConfigService) {
    const node = this.configService.get<string>('elasticsearch.node')
    const apiKey = this.configService.get<string>('elasticsearch.apiKey')

    if (!node || !apiKey) {
      throw new Error('Elasticsearch configuration is missing')
    }

    this.client = new Client({
      node,
      auth: {
        apiKey
      },
      tls: {
        rejectUnauthorized: false
      }
    })
  }

  async onModuleInit() {
    try {
      await this.client.info()
      this.logger.log('✅ Connected to Elasticsearch successfully')

      // Tạo index nếu chưa tồn tại
      await this.createProductIndex()
    } catch (error) {
      this.logger.error('❌ Failed to connect to Elasticsearch', error)
      throw error
    }
  }

  /**
   * Tạo index cho sản phẩm với mapping tối ưu
   */
  private async createProductIndex() {
    const indexName = this.configService.get<string>('elasticsearch.index.products', 'products_v1')
    const exists = await this.client.indices.exists({ index: indexName })

    if (!exists) {
      this.logger.log(`Creating index "${indexName}" with optimized mapping...`)

      await this.client.indices.create({
        index: indexName,
        settings: {
          analysis: {
            analyzer: {
              vietnamese_analyzer: {
                type: 'custom',
                tokenizer: 'standard',
                filter: ['lowercase', 'asciifolding']
              }
            }
          }
        },
        mappings: {
          properties: {
            skuId: { type: 'keyword' },
            productId: { type: 'keyword' },
            skuValue: { type: 'keyword' },
            skuPrice: { type: 'double' },
            skuStock: { type: 'integer' },
            skuImage: { type: 'keyword', index: false },
            productName: {
              type: 'text',
              analyzer: 'vietnamese_analyzer',
              fields: { keyword: { type: 'keyword' } }
            },
            productDescription: {
              type: 'text',
              analyzer: 'vietnamese_analyzer'
            },
            productImages: { type: 'keyword', index: false },
            brandId: { type: 'keyword' },
            brandName: { type: 'keyword' },
            categoryIds: { type: 'keyword' },
            categoryNames: { type: 'keyword' },
            specifications: { type: 'object', enabled: false },
            variants: { type: 'object', enabled: false },
            attrs: {
              type: 'nested',
              properties: {
                attrName: { type: 'keyword' },
                attrValue: { type: 'keyword' }
              }
            },
            createdAt: { type: 'date' },
            updatedAt: { type: 'date' }
          }
        }
      })

      this.logger.log(`✅ Index "${indexName}" created successfully`)
    }
  }

  /**
   * Bulk index documents
   */
  async bulkIndex(index: string, docs: any[], idField: string = 'skuId') {
    if (!docs.length) {
      this.logger.warn('No documents to index')
      return
    }

    const operations = docs.flatMap((doc) => [{ index: { _index: index, _id: doc[idField] } }, doc])

    try {
      const result = await this.client.bulk({
        refresh: true,
        operations
      })

      if (result.errors) {
        this.logger.error(
          'Bulk index errors:',
          result.items.filter((item) => item.index?.error)
        )
      } else {
        this.logger.log(`✅ Successfully indexed ${docs.length} documents`)
      }

      return result
    } catch (error) {
      this.logger.error('Bulk index failed:', error)
      throw error
    }
  }

  /**
   * Delete document by ID
   */
  async deleteById(index: string, id: string) {
    try {
      await this.client.delete({ index, id })
      this.logger.log(`✅ Deleted document ${id} from index ${index}`)
    } catch (error) {
      this.logger.error(`Failed to delete document ${id}:`, error)
      throw error
    }
  }

  /**
   * Search documents
   */
  async search(
    index: string,
    query: any,
    options: {
      size?: number
      from?: number
      sort?: any[]
    } = {}
  ) {
    try {
      const { size = 20, from = 0, sort } = options

      const result = await this.client.search({
        index,
        query,
        size,
        from,
        sort,
        collapse: { field: 'productId' } // Tránh duplicate products
      })

      return result
    } catch (error) {
      this.logger.error('Search failed:', error)
      throw error
    }
  }

  /**
   * Check if document exists
   */
  async exists(index: string, id: string): Promise<boolean> {
    try {
      const result = await this.client.exists({ index, id })
      return result
    } catch (error) {
      this.logger.error(`Failed to check document existence ${id}:`, error)
      return false
    }
  }
}
