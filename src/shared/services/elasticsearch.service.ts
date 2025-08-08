import { Injectable, Logger, OnModuleInit } from '@nestjs/common'
import { Client } from '@elastic/elasticsearch'
import { ConfigService } from '@nestjs/config'

@Injectable()
export class ElasticsearchService implements OnModuleInit {
  private readonly logger = new Logger(ElasticsearchService.name)
  public readonly client: Client

  constructor(private readonly configService: ConfigService) {
    const node = this.configService.get<string>('ELASTICSEARCH_NODE')
    const username = this.configService.get<string>('ELASTICSEARCH_USERNAME')
    const password = this.configService.get<string>('ELASTICSEARCH_PASSWORD')
    const sslEnabled = this.configService.get<boolean>('ELASTICSEARCH_SSL_ENABLED', false)

    if (!node) {
      throw new Error('Elasticsearch configuration is missing: ELASTICSEARCH_NODE')
    }

    const clientConfig: any = {
      node,
      // Tăng timeout cho kết nối từ xa
      requestTimeout: 120000, // 2 phút
      maxRetries: 3,
      retryOnTimeout: true
    }

    // Chỉ thêm auth nếu có username và password
    if (username && password) {
      clientConfig.auth = { username, password }
    }

    // Chỉ thêm tls nếu SSL được bật
    if (sslEnabled) {
      clientConfig.tls = { rejectUnauthorized: false }
    }

    this.client = new Client(clientConfig)
  }

  async onModuleInit() {
    try {
      await this.client.info()
      this.logger.log('Connected to Elasticsearch successfully')
      await this.createProductIndex()
    } catch (error) {
      this.logger.error('Failed to connect to Elasticsearch', error)
      throw error
    }
  }

  /**
   * Tạo index cho sản phẩm với mapping tối ưu
   */
  private async createProductIndex() {
    const indexName = this.configService.get<string>('ELASTICSEARCH_INDEX_PRODUCTS', 'products_v1')
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
                filter: ['lowercase', 'asciifolding', 'trim']
              },
              vietnamese_search_analyzer: {
                type: 'custom',
                tokenizer: 'standard',
                filter: ['lowercase', 'asciifolding', 'trim']
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
              search_analyzer: 'vietnamese_search_analyzer',
              fields: {
                keyword: { type: 'keyword' },
                raw: { type: 'text', analyzer: 'standard' }
              }
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

      this.logger.log(`Index "${indexName}" created successfully`)
    }
  }

  /**
   * Search documents với options tối ưu
   */
  async search(
    index: string,
    query: any,
    options: {
      size?: number
      from?: number
      sort?: any[]
      timeout?: number
      aggs?: any
    } = {}
  ) {
    try {
      const { size = 20, from = 0, sort, timeout = 30000, aggs } = options

      const searchParams: any = {
        index,
        query,
        size,
        from,
        sort,
        collapse: { field: 'productId' },
        timeout: `${timeout}ms`
      }

      if (aggs) {
        searchParams.aggs = aggs
      }

      const startTime = Date.now()
      const result = await this.client.search(searchParams)
      const endTime = Date.now()

      this.logger.log(`Search completed in ${endTime - startTime}ms, found ${result.hits.total} results`)

      return result
    } catch (error) {
      this.logger.error('Search failed:', error)
      throw error
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
        operations,
        timeout: '120s' // Tăng timeout lên 2 phút
      })

      if (result.errors) {
        this.logger.error(
          'Bulk index errors:',
          result.items.filter((item) => item.index?.error)
        )
      } else {
        this.logger.log(`Successfully indexed ${docs.length} documents`)
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
      this.logger.log(`Deleted document ${id} from index ${index}`)
    } catch (error) {
      this.logger.error(`Failed to delete document ${id}:`, error)
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
