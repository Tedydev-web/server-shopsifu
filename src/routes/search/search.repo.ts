import { Injectable, Logger } from '@nestjs/common'
import { PrismaService } from 'src/shared/services/prisma.service'
import { ElasticsearchService } from 'src/shared/services/elasticsearch.service'
import { ConfigService } from '@nestjs/config'
import { SearchProductsQueryType, SearchProductsResType } from './search.model'
import { SyncProductJobType, SyncProductsBatchJobType } from 'src/shared/models/search-sync.model'
import { ES_INDEX_PRODUCTS } from 'src/shared/constants/search-sync.constant'
import { OrderBy, SortBy } from 'src/shared/constants/other.constant'

@Injectable()
export class SearchRepo {
  private readonly logger = new Logger(SearchRepo.name)

  constructor(
    private readonly prisma: PrismaService,
    private readonly es: ElasticsearchService,
    private readonly configService: ConfigService
  ) {}

  /**
   * Tìm kiếm sản phẩm trong Elasticsearch
   */
  async searchProducts(query: SearchProductsQueryType): Promise<SearchProductsResType> {
    const { q, page = 1, limit = 20, orderBy = OrderBy.Desc, sortBy = SortBy.CreatedAt, filters } = query

    // Build Elasticsearch query
    const esQuery: any = {
      bool: {
        must: []
      }
    }

    // Text search
    if (q && q.trim()) {
      esQuery.bool.must.push({
        multi_match: {
          query: q,
          fields: ['productName^2', 'productDescription', 'skuValue'],
          type: 'best_fields',
          fuzziness: 'AUTO'
        }
      })
    }

    // Filters
    if (filters) {
      const filterClauses: any[] = []

      if (filters.brandIds?.length) {
        filterClauses.push({
          terms: { brandId: filters.brandIds }
        })
      }

      if (filters.categoryIds?.length) {
        filterClauses.push({
          terms: { categoryIds: filters.categoryIds }
        })
      }

      if (filters.minPrice !== undefined || filters.maxPrice !== undefined) {
        const rangeFilter: any = { skuPrice: {} }
        if (filters.minPrice !== undefined) rangeFilter.skuPrice.gte = filters.minPrice
        if (filters.maxPrice !== undefined) rangeFilter.skuPrice.lte = filters.maxPrice
        filterClauses.push({ range: rangeFilter })
      }

      if (filters.attrs?.length) {
        const nestedQueries = filters.attrs.map((attr) => ({
          nested: {
            path: 'attrs',
            query: {
              bool: {
                must: [{ term: { 'attrs.attrName': attr.attrName } }, { term: { 'attrs.attrValue': attr.attrValue } }]
              }
            }
          }
        }))
        filterClauses.push(...nestedQueries)
      }

      if (filterClauses.length > 0) {
        esQuery.bool.filter = filterClauses
      }
    }

    // Build sort options
    const sortOptions: any[] = []

    if (sortBy === SortBy.Price) {
      sortOptions.push({ skuPrice: { order: orderBy.toLowerCase() } })
    } else if (sortBy === SortBy.Sale) {
      // Note: ES doesn't have sale count field, using score as fallback
      sortOptions.push({ _score: { order: 'desc' } })
    } else {
      // Default: CreatedAt
      sortOptions.push({ createdAt: { order: orderBy.toLowerCase() } })
    }

    // Add score as secondary sort
    sortOptions.push({ _score: { order: 'desc' } })

    try {
      this.logger.log('🔍 Executing search with query:', JSON.stringify(esQuery, null, 2))

      const from = (page - 1) * limit

      const result = await this.es.search(ES_INDEX_PRODUCTS, esQuery, {
        size: limit,
        from: from,
        sort: sortOptions
      })

      this.logger.log('✅ Search completed successfully')

      const hits = result.hits.hits.map((hit: any) => hit._source)
      const total = typeof result.hits.total === 'object' ? result.hits.total.value : result.hits.total || 0
      const totalPages = Math.ceil(total / limit)

      return {
        data: hits,
        metadata: {
          totalItems: total,
          page,
          limit,
          totalPages,
          hasNext: page < totalPages,
          hasPrev: page > 1
        }
      }
    } catch (error) {
      this.logger.error('❌ Search products failed:', error)
      this.logger.error('❌ Error details:', {
        message: error.message,
        stack: error.stack,
        name: error.name
      })
      throw error
    }
  }
}
