import { createZodDto } from 'nestjs-zod'
import { BasePaginationQuerySchema } from 'src/shared/models/pagination.model'

export class BasePaginationQueryDTO extends createZodDto(BasePaginationQuerySchema) {}
