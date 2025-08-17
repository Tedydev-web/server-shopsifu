import { Injectable, Logger } from '@nestjs/common'
import { PrismaService } from 'src/shared/services/prisma.service'
import { ElasticsearchService } from 'src/shared/services/elasticsearch.service'
import { ConfigService } from '@nestjs/config'
import { SearchProductsQueryType, SearchProductsResType } from './search.model'
import { OrderBy, SortBy } from 'src/shared/constants/other.constant'
import { ElasticsearchConnectionException, ElasticsearchQueryException, SearchTimeoutException } from './search.error'

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

    const esQuery: any = {
      bool: {
        must: []
      }
    }

    // Text search trong productName
    if (q && q.trim()) {
      const searchTerms = q
        .trim()
        .toLowerCase()
        .split(' ')
        .filter((term) => term.length > 0)

      if (searchTerms.length > 0) {
        const multiMatchQuery = {
          multi_match: {
            query: q,
            fields: ['productName^3'],
            type: 'best_fields',
            operator: 'and',
            fuzziness: 'AUTO',
            minimum_should_match: '75%'
          }
        }

        esQuery.bool.must.push(multiMatchQuery)

        const shouldClauses = searchTerms.map((term) => ({
          multi_match: {
            query: term,
            fields: ['productName^2'],
            type: 'phrase',
            boost: 2
          }
        }))

        if (shouldClauses.length > 0) {
          esQuery.bool.should = shouldClauses
          esQuery.bool.minimum_should_match = 1
        }
      }
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

    // Sort options
    const sortOptions: any[] = []

    if (sortBy === SortBy.Price) {
      sortOptions.push({ skuPrice: { order: orderBy.toLowerCase() } })
    } else if (sortBy === SortBy.Sale) {
      sortOptions.push({ _score: { order: 'desc' } })
    } else {
      sortOptions.push({ createdAt: { order: orderBy.toLowerCase() } })
    }

    sortOptions.push({ _score: { order: 'desc' } })

    try {
      const from = (page - 1) * limit

      const result = await this.es.search(
        this.configService.get('elasticsearch.index.products') || 'products',
        esQuery,
        {
          size: limit,
          from: from,
          sort: sortOptions
        }
      )

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
      this.logger.error('Search products failed:', error)

      // Phân loại lỗi dựa trên error type
      if (error.name === 'ConnectionError' || error.code === 'ECONNREFUSED') {
        throw ElasticsearchConnectionException
      }

      if (error.name === 'TimeoutError' || error.message?.includes('timeout')) {
        throw SearchTimeoutException
      }

      throw ElasticsearchQueryException
    }
  }
}
