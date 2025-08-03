import { createZodDto } from 'nestjs-zod'
import { SearchProductsQuerySchema, SearchProductsResSchema } from './search.model'

export class SearchProductsQueryDTO extends createZodDto(SearchProductsQuerySchema) {}

export class SearchProductsResDTO extends createZodDto(SearchProductsResSchema) {}
