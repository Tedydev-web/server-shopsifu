import { Controller, Get, Query } from '@nestjs/common'
import { SearchSyncService } from 'src/shared/services/search-sync.service'
import { SearchQueryType } from 'src/shared/models/search-sync.model'

@Controller('search')
export class SearchController {
  constructor(private readonly searchSyncService: SearchSyncService) {}

  /**
   * Tìm kiếm sản phẩm trong Elasticsearch
   */
  @Get('products')
  async searchProducts(@Query() query: SearchQueryType) {
    const { q, filters, pagination, sort } = query

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

    // Build sort
    const sortOptions: any[] = []
    if (sort?.field && sort?.order) {
      if (sort.field === '_score') {
        sortOptions.push({ _score: { order: sort.order } })
      } else {
        sortOptions.push({ [sort.field]: { order: sort.order } })
      }
    }

    // Build pagination
    const page = pagination?.page || 1
    const limit = Math.min(pagination?.limit || 20, 100)
    const from = (page - 1) * limit

    try {
      const result = await this.searchSyncService.searchProducts(esQuery, {
        size: limit,
        from,
        sort: sortOptions
      })

      return {
        success: true,
        data: {
          hits: result.hits.hits.map((hit) => hit._source),
          total: result.hits.total,
          page,
          limit,
          totalPages: Math.ceil((result.hits.total as number) / limit)
        }
      }
    } catch (error) {
      return {
        success: false,
        error: error.message
      }
    }
  }
}
