import { Injectable, Logger } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { SearchRepo } from './search.repo'
import { SearchProductsQueryType, SearchProductsResType } from './search.model'
import { I18nService } from 'nestjs-i18n'
import { ElasticsearchService } from 'src/shared/services/elasticsearch.service'
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
  private dictionaryCache: Map<string, { normalizedValue: string; synonyms: string[] }[]> | null = null
  private cacheExpiry: number = 0
  private readonly CACHE_DURATION = 30 * 60 * 1000 // 30 phút

  constructor(
    private readonly searchRepo: SearchRepo,
    private readonly esService: ElasticsearchService,
    private readonly i18n: I18nService,
    private readonly configService: ConfigService
  ) {}

  /**
   * Lấy dictionary động từ Elasticsearch Aggregations, có cache
   */
  private async getDictionary(): Promise<Map<string, { normalizedValue: string; synonyms: string[] }[]>> {
    if (this.dictionaryCache && Date.now() < this.cacheExpiry) {
      return this.dictionaryCache
    }

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

      const dictionary = new Map<string, { normalizedValue: string; synonyms: string[] }[]>()
      const attrBuckets = (result.aggregations as any)?.unique_attrs?.attr_names?.buckets || []

      for (const attrBucket of attrBuckets) {
        const attrName = attrBucket.key
        const values = attrBucket.attr_values.buckets.map((v: any) => ({
          normalizedValue: v.key,
          synonyms: [v.key.toLowerCase()]
        }))
        dictionary.set(attrName, values)
      }

      this.dictionaryCache = dictionary
      this.cacheExpiry = Date.now() + this.CACHE_DURATION
      return dictionary
    } catch {
      throw DictionaryLoadException
    }
  }

  /**
   * Parse natural language query thành structured query
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
    } catch {
      throw DictionaryParseException
    }
  }

  /**
   * Tìm kiếm sản phẩm
   */
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
}
