import { createZodDto } from 'nestjs-zod'
import { SearchProductsQuerySchema, SearchProductsResSchema, QueueInfoResSchema } from './search.model'

export class SearchProductsQueryDTO extends createZodDto(SearchProductsQuerySchema) {}

export class SearchProductsResDTO extends createZodDto(SearchProductsResSchema) {}

export class QueueInfoResDTO extends createZodDto(QueueInfoResSchema) {}
