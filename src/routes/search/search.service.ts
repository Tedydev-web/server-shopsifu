import { Injectable, Logger } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { SearchRepo } from './search.repo'
import { SearchProductsQueryType, SearchProductsResType } from './search.model'
import { I18nService } from 'nestjs-i18n'
import { ElasticsearchService } from 'src/shared/services/elasticsearch.service'
import { RedisService } from 'src/shared/services/redis.service'
import { Cacheable } from 'src/shared/decorators/cacheable.decorator'
import {
  EmptySearchQueryException,
  SearchQueryTooShortException,
  DictionaryLoadException,
  DictionaryParseException
} from './search.error'

interface ParsedQuery {
  q: string
  options: { name: string; value: string }[]
}

@Injectable()
export class SearchService {
  private readonly logger = new Logger(SearchService.name)

  constructor(
    private readonly searchRepo: SearchRepo,
    private readonly esService: ElasticsearchService,
    private readonly i18n: I18nService,
    private readonly configService: ConfigService,
    private readonly redisService: RedisService
  ) {}

  /**
   * 📚 Dictionary cache với Redis - optimize search parsing
   * Cache dictionary attributes để parse natural language queries
   */
  @Cacheable({
    key: 'search:dictionary',
    ttl: 1800, // 30 minutes
    scope: 'module',
    moduleName: 'SearchModule'
  })
  private async getDictionaryRaw(): Promise<Record<string, { normalizedValue: string; synonyms: string[] }[]>> {
    try {
      const result = await this.esService.client.search({
        index: this.configService.get('elasticsearch.index.products'),
        size: 0,
        aggs: {
          unique_attrs: {
            nested: { path: 'attrs' },
            aggs: {
              attr_names: {
                terms: { field: 'attrs.attrName', size: 100 },
                aggs: {
                  attr_values: {
                    terms: { field: 'attrs.attrValue', size: 100 }
                  }
                }
              }
            }
          }
        }
      })

      const dictionary: Record<string, { normalizedValue: string; synonyms: string[] }[]> = {}
      const attrBuckets = (result.aggregations as any)?.unique_attrs?.attr_names?.buckets || []

      for (const attrBucket of attrBuckets) {
        const attrName = attrBucket.key
        const values = attrBucket.attr_values.buckets.map((v: any) => ({
          normalizedValue: v.key,
          synonyms: [v.key.toLowerCase()]
        }))
        dictionary[attrName] = values
      }

      return dictionary
    } catch (error) {
      this.logger.warn('Elasticsearch dictionary aggregation failed:', error)
      // Return empty dictionary instead of throwing
      return {}
    }
  }

  /**
   * 🗺️ Get dictionary as Map (wrapper for cached version)
   * ⚡ Graceful fallback nếu cache fails
   */
  private async getDictionary(): Promise<Map<string, { normalizedValue: string; synonyms: string[] }[]>> {
    try {
      const dictionaryRecord = await this.getDictionaryRaw()
      return new Map(Object.entries(dictionaryRecord))
    } catch (error) {
      this.logger.warn('Dictionary cache failed, returning empty dictionary:', error)
      return new Map() // Return empty Map để không break parsing logic
    }
  }

  /**
   * Parse natural language query thành structured query
   * ⚡ Graceful fallback nếu dictionary fails
   */
  private async parseQuery(rawQuery: string): Promise<ParsedQuery> {
    try {
      const dictionary = await this.getDictionary()
      const tokens = rawQuery.toLowerCase().split(' ').filter(Boolean)
      const searchTextParts: string[] = []
      const foundOptions: { name: string; value: string }[] = []
      const consumedTokens = new Set<string>()

      for (const token of tokens) {
        if (consumedTokens.has(token)) continue

        let found = false
        for (const [optionName, values] of dictionary.entries()) {
          const foundValue = values.find((v) => v.synonyms.includes(token))
          if (foundValue) {
            foundOptions.push({ name: optionName, value: foundValue.normalizedValue })
            consumedTokens.add(token)
            found = true
            break
          }
        }

        if (!found) {
          searchTextParts.push(token)
        }
      }

      return {
        q: searchTextParts.join(' '),
        options: foundOptions
      }
    } catch (error) {
      this.logger.warn('Dictionary parsing failed, falling back to simple search:', error)
      // Graceful fallback - return original query without parsing
      return {
        q: rawQuery,
        options: []
      }
    }
  }

  /**
   * 🔍 Intelligent search caching với adaptive TTL
   * Popular searches cache lâu hơn, complex searches cache ngắn hơn
   */
  @Cacheable({
    key: 'search:products',
    ttl: 900, // 15 minutes base TTL
    scope: 'module',
    moduleName: 'SearchModule',
    keyGenerator: (query: SearchProductsQueryType) => {
      // Create smart cache key - inline logic to avoid 'this' context issues
      const hasComplexFilters = (filters?: any): boolean => {
        if (!filters) return false
        const filterCount = [
          filters.brandIds?.length > 0,
          filters.categoryIds?.length > 0,
          filters.minPrice !== undefined,
          filters.maxPrice !== undefined,
          filters.attrs?.length > 0
        ].filter(Boolean).length
        return filterCount >= 2
      }

      // Determine search type
      let searchType = 'default'
      if (!query.q?.trim() && !hasComplexFilters(query.filters)) {
        searchType = 'browse'
      } else if (query.q?.trim() && !hasComplexFilters(query.filters)) {
        searchType = 'simple'
      } else if (hasComplexFilters(query.filters)) {
        searchType = 'complex'
      }

      // Generate compact hash
      const searchData = {
        q: query.q?.trim().toLowerCase() || '',
        p: query.page || 1,
        l: query.limit || 20,
        o: query.orderBy,
        s: query.sortBy,
        f: query.filters
          ? {
              b: query.filters.brandIds?.sort().join(',') || '',
              c: query.filters.categoryIds?.sort().join(',') || '',
              min: query.filters.minPrice || 0,
              max: query.filters.maxPrice || 0,
              a:
                query.filters.attrs
                  ?.map((attr) => `${attr.attrName}:${attr.attrValue}`)
                  .sort()
                  .join('|') || ''
            }
          : {}
      }

      const queryHash = Buffer.from(JSON.stringify(searchData))
        .toString('base64')
        .replace(/[=+/]/g, '')
        .substring(0, 16)
      return `${searchType}:${queryHash}`
    },
    condition: (result: SearchProductsResType) => {
      // Only cache successful results with data
      return result && result.data && result.data.length > 0
    }
  })
  async searchProducts(query: SearchProductsQueryType): Promise<SearchProductsResType> {
    // Validate query trước khi parse
    if (query.q) {
      const trimmedQuery = query.q.trim()
      if (!trimmedQuery) {
        throw EmptySearchQueryException
      }
      if (trimmedQuery.length < 1) {
        throw SearchQueryTooShortException
      }
    }

    if (query.q && query.q.trim()) {
      const parsedQuery = await this.parseQuery(query.q)

      if (parsedQuery.options.length > 0) {
        const parsedAttrs = parsedQuery.options.map((opt) => ({
          attrName: opt.name,
          attrValue: opt.value
        }))
        query.filters = {
          ...query.filters,
          attrs: [...(query.filters?.attrs || []), ...parsedAttrs]
        }
      }

      query.q = parsedQuery.q
    }

    const result = await this.searchRepo.searchProducts(query)

    return {
      message: this.i18n.t('search.search.success.SEARCH_SUCCESS'),
      data: result.data,
      metadata: result.metadata
    }
  }

  /**
   * 🎯 Phân loại search type để optimize cache strategy
   */
  private getSearchType(query: SearchProductsQueryType): string {
    // Browse all (no search query, minimal filters)
    if (!query.q?.trim() && !this.hasComplexFilters(query.filters)) {
      return 'browse' // Cache lâu nhất
    }

    // Simple search (chỉ có text query)
    if (query.q?.trim() && !this.hasComplexFilters(query.filters)) {
      return 'simple' // Cache trung bình
    }

    // Complex search (có nhiều filters)
    if (this.hasComplexFilters(query.filters)) {
      return 'complex' // Cache ngắn nhất
    }

    return 'default'
  }

  /**
   * 🔧 Check if search has complex filters
   */
  private hasComplexFilters(filters?: any): boolean {
    if (!filters) return false

    const filterCount = [
      filters.brandIds?.length > 0,
      filters.categoryIds?.length > 0,
      filters.minPrice !== undefined,
      filters.maxPrice !== undefined,
      filters.attrs?.length > 0
    ].filter(Boolean).length

    return filterCount >= 2 // 2+ filters = complex
  }

  /**
   * 🔑 Generate compact hash for search parameters
   */
  private generateSearchHash(query: SearchProductsQueryType): string {
    const searchData = {
      q: query.q?.trim().toLowerCase() || '',
      p: query.page || 1,
      l: query.limit || 20,
      o: query.orderBy,
      s: query.sortBy,
      f: query.filters
        ? {
            b: query.filters.brandIds?.sort().join(',') || '',
            c: query.filters.categoryIds?.sort().join(',') || '',
            min: query.filters.minPrice || 0,
            max: query.filters.maxPrice || 0,
            a:
              query.filters.attrs
                ?.map((attr) => `${attr.attrName}:${attr.attrValue}`)
                .sort()
                .join('|') || ''
          }
        : {}
    }

    // Create compact hash using Buffer.from + base64
    return Buffer.from(JSON.stringify(searchData)).toString('base64').replace(/[=+/]/g, '').substring(0, 16)
  }
}
