import { BadRequestException, InternalServerErrorException, ServiceUnavailableException } from '@nestjs/common'

// Search query related errors
export const InvalidSearchQueryException = new BadRequestException([
  {
    message: 'search.search.error.INVALID_QUERY',
    path: 'q'
  }
])

export const EmptySearchQueryException = new BadRequestException([
  {
    message: 'search.search.error.EMPTY_QUERY',
    path: 'q'
  }
])

export const SearchQueryTooShortException = new BadRequestException([
  {
    message: 'search.search.error.QUERY_TOO_SHORT',
    path: 'q'
  }
])

// Search filters related errors
export const InvalidSearchFiltersException = new BadRequestException([
  {
    message: 'search.search.error.INVALID_FILTERS',
    path: 'filters'
  }
])

export const InvalidPriceRangeException = new BadRequestException([
  {
    message: 'search.search.error.INVALID_PRICE_RANGE',
    path: 'filters'
  }
])

export const InvalidAttributeFilterException = new BadRequestException([
  {
    message: 'search.search.error.INVALID_ATTRIBUTE_FILTER',
    path: 'filters'
  }
])

// Elasticsearch related errors
export const ElasticsearchConnectionException = new ServiceUnavailableException(
  'search.search.error.ELASTICSEARCH_CONNECTION_FAILED'
)

export const ElasticsearchQueryException = new InternalServerErrorException(
  'search.search.error.ELASTICSEARCH_QUERY_FAILED'
)

export const ElasticsearchIndexNotFoundException = new InternalServerErrorException(
  'search.search.error.ELASTICSEARCH_INDEX_NOT_FOUND'
)

// Search results related errors
export const SearchTimeoutException = new ServiceUnavailableException('search.search.error.SEARCH_TIMEOUT')

export const SearchServiceUnavailableException = new ServiceUnavailableException(
  'search.search.error.SEARCH_SERVICE_UNAVAILABLE'
)

// Dictionary related errors
export const DictionaryLoadException = new InternalServerErrorException('search.search.error.DICTIONARY_LOAD_FAILED')

export const DictionaryParseException = new BadRequestException('search.search.error.DICTIONARY_PARSE_FAILED')
